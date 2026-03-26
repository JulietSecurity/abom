package advisory

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/julietsecurity/abom/pkg/model"
)

const (
	remoteURL = "https://raw.githubusercontent.com/JulietSecurity/abom-advisories/main/db/advisories.json"
	cacheTTL  = 1 * time.Hour
	fetchTimeout = 5 * time.Second
)

// AdvisoryDB is the top-level JSON structure for the advisory database.
type AdvisoryDB struct {
	SchemaVersion string     `json:"schema_version"`
	LastUpdated   string     `json:"last_updated"`
	Advisories    []Advisory `json:"advisories"`
}

// Advisory describes a known-compromised action.
type Advisory struct {
	ID                 string           `json:"id"`
	Title              string           `json:"title"`
	CVE                string           `json:"cve,omitempty"`
	CVSS               float64          `json:"cvss,omitempty"`
	Published          string           `json:"published"`
	Updated            string           `json:"updated"`
	Status             string           `json:"status"`
	Description        string           `json:"description"`
	References         []string         `json:"references,omitempty"`
	AffectedActions    []AffectedAction `json:"affected_actions"`
	Indicators         *Indicators      `json:"indicators,omitempty"`
	RecommendedActions []string         `json:"recommended_actions,omitempty"`
}

// AffectedAction describes an action affected by an advisory.
type AffectedAction struct {
	Uses           string       `json:"uses"`
	AffectedRefs   AffectedRefs `json:"affected_refs"`
	AffectedPeriod struct {
		From string  `json:"from"`
		To   *string `json:"to"`
	} `json:"affected_period"`
	ToolNames []string `json:"tool_names,omitempty"`
}

// AffectedRefs describes which refs of an action are affected.
type AffectedRefs struct {
	Tags     []string `json:"tags,omitempty"`
	TagRange string   `json:"tag_range,omitempty"`
	SafeTags []string `json:"safe_tags,omitempty"`
	SafeSHAs []string `json:"safe_shas,omitempty"`
}

// Indicators contains IOCs for an advisory.
type Indicators struct {
	DockerImages  []string `json:"docker_images,omitempty"`
	ReposToCheck  []string `json:"repos_to_check,omitempty"`
	Notes         string   `json:"notes,omitempty"`
}

// LoadOptions configures how the advisory database is loaded.
type LoadOptions struct {
	Offline bool
	NoCache bool
	Quiet   bool
	Token   string
}

// Database holds loaded advisories and provides matching.
type Database struct {
	db     AdvisoryDB
	source string // "remote", "cache", "builtin"
}

// NewDatabase loads the advisory database using the fallback chain:
// remote -> cache -> builtin.
func NewDatabase(opts LoadOptions) *Database {
	// Try remote first (unless offline)
	if !opts.Offline {
		if db, err := loadRemote(opts); err == nil {
			if !opts.NoCache {
				_ = writeCache(db)
			}
			return &Database{db: *db, source: "remote"}
		}
	}

	// Try cache (unless no-cache)
	if !opts.NoCache && !opts.Offline {
		if db, fresh, err := loadCache(); err == nil {
			if !fresh && !opts.Quiet {
				fmt.Fprintf(os.Stderr, "Warning: using cached advisory data from %s. Run with network access for latest advisories.\n", db.LastUpdated)
			}
			return &Database{db: *db, source: "cache"}
		}
	}

	// Fall back to builtin
	db, _ := parseAdvisoryDB(builtinData)
	if !opts.Offline && !opts.Quiet {
		fmt.Fprintf(os.Stderr, "Warning: using built-in advisory data from %s. Run with network access for latest advisories.\n", db.LastUpdated)
	}
	return &Database{db: *db, source: "builtin"}
}

// Check returns the first matching advisory for an action ref, or nil.
// If the ref is a SHA not in safe_shas, returns the advisory with a
// "verify manually" note.
func (d *Database) Check(ref *model.ActionRef) (*Advisory, string) {
	for i := range d.db.Advisories {
		adv := &d.db.Advisories[i]
		if adv.Status == "withdrawn" {
			continue
		}
		for _, aa := range adv.AffectedActions {
			if matchResult := matchAction(ref, &aa); matchResult != "" {
				return adv, matchResult
			}
		}
		// Check docker image indicators
		if ref.ActionType == model.ActionTypeDocker && adv.Indicators != nil {
			for _, img := range adv.Indicators.DockerImages {
				if strings.HasPrefix(ref.Path, img) || strings.HasPrefix(ref.Path, strings.Split(img, ":")[0]) {
					return adv, "compromised"
				}
			}
		}

		// Check detected tools — actions that wrap a compromised tool
		if len(ref.DetectedTools) > 0 {
			for _, aa := range adv.AffectedActions {
				toolNames := aa.ToolNames
				// Infer tool name from uses if tool_names not set
				if len(toolNames) == 0 {
					toolNames = inferToolNames(aa.Uses)
				}
				for _, tool := range toolNames {
					for _, detected := range ref.DetectedTools {
						if strings.EqualFold(tool, detected) {
							return adv, "detected-tool"
						}
					}
				}
			}
		}
	}
	return nil, ""
}

// CheckAll annotates all actions in an ABOM with advisory data.
func (d *Database) CheckAll(abom *model.ABOM) {
	for _, wf := range abom.Workflows {
		for _, job := range wf.Jobs {
			for _, step := range job.Steps {
				if step.Action != nil {
					d.checkAction(step.Action)
				}
			}
		}
	}
}

func (d *Database) checkAction(ref *model.ActionRef) {
	if adv, result := d.Check(ref); adv != nil {
		ref.Compromised = true
		switch result {
		case "verify-sha":
			ref.Advisory = adv.ID + " (SHA — verify manually)"
		case "detected-tool":
			ref.Advisory = adv.ID + " (detected via action inputs)"
		default:
			ref.Advisory = adv.ID
		}
	}
	for _, dep := range ref.Dependencies {
		d.checkAction(dep)
	}
}

// matchAction checks if an ActionRef matches an AffectedAction entry.
// Returns "compromised", "verify-sha", or "" (no match).
func matchAction(ref *model.ActionRef, aa *AffectedAction) string {
	// Parse uses into owner/repo
	parts := strings.SplitN(aa.Uses, "/", 2)
	if len(parts) != 2 {
		return ""
	}
	owner, repo := parts[0], parts[1]

	if !strings.EqualFold(ref.Owner, owner) || !strings.EqualFold(ref.Repo, repo) {
		return ""
	}

	// Check safe_tags first
	for _, safe := range aa.AffectedRefs.SafeTags {
		if ref.Ref == safe {
			return ""
		}
	}

	// Check safe_shas
	for _, safe := range aa.AffectedRefs.SafeSHAs {
		if strings.EqualFold(ref.Ref, safe) {
			return ""
		}
	}

	// If ref is a SHA and not in safe_shas, flag as "verify manually"
	if ref.RefType == model.RefTypeSHA {
		return "verify-sha"
	}

	// Check explicit tag list
	if len(aa.AffectedRefs.Tags) > 0 {
		for _, tag := range aa.AffectedRefs.Tags {
			if ref.Ref == tag {
				return "compromised"
			}
		}
	}

	// Check tag range
	if aa.AffectedRefs.TagRange != "" {
		if matchesTagRange(ref.Ref, aa.AffectedRefs.TagRange) {
			return "compromised"
		}
	}

	return ""
}

// inferToolNames extracts likely tool names from an action uses field.
// e.g., "aquasecurity/trivy-action" -> ["trivy"]
// e.g., "aquasecurity/setup-trivy" -> ["trivy"]
func inferToolNames(uses string) []string {
	parts := strings.SplitN(uses, "/", 2)
	if len(parts) != 2 {
		return nil
	}
	repo := strings.ToLower(parts[1])

	// Common patterns: {tool}-action, setup-{tool}, ghaction-{tool}-scan, etc.
	// Extract candidate tool names by removing common suffixes/prefixes
	candidates := []string{repo}
	for _, prefix := range []string{"setup-", "ghaction-", "action-"} {
		if strings.HasPrefix(repo, prefix) {
			candidates = append(candidates, strings.TrimPrefix(repo, prefix))
		}
	}
	for _, suffix := range []string{"-action", "-scan", "-check", "-lint"} {
		if strings.HasSuffix(repo, suffix) {
			candidates = append(candidates, strings.TrimSuffix(repo, suffix))
		}
	}

	// Known tool name mappings
	knownTools := map[string]string{
		"trivy":  "trivy",
		"grype":  "grype",
		"snyk":   "snyk",
		"cosign": "cosign",
		"syft":   "syft",
	}

	var tools []string
	for _, candidate := range candidates {
		// Check if any known tool name appears in the candidate
		for _, toolName := range knownTools {
			if strings.Contains(candidate, toolName) {
				found := false
				for _, t := range tools {
					if t == toolName {
						found = true
						break
					}
				}
				if !found {
					tools = append(tools, toolName)
				}
			}
		}
	}

	return tools
}

// matchesTagRange parses a range like ">=v0.0.1 <=v0.34.2" and checks if
// the given version falls within it.
func matchesTagRange(version, rangeStr string) bool {
	// Parse range components (e.g., ">=v0.0.1 <=v0.34.2")
	parts := strings.Fields(rangeStr)
	v := normalizeVersion(version)
	if v == "" {
		return false
	}

	for _, part := range parts {
		if strings.HasPrefix(part, ">=") {
			min := normalizeVersion(strings.TrimPrefix(part, ">="))
			if v < min {
				return false
			}
		} else if strings.HasPrefix(part, "<=") {
			max := normalizeVersion(strings.TrimPrefix(part, "<="))
			if v > max {
				return false
			}
		} else if strings.HasPrefix(part, ">") {
			min := normalizeVersion(strings.TrimPrefix(part, ">"))
			if v <= min {
				return false
			}
		} else if strings.HasPrefix(part, "<") {
			max := normalizeVersion(strings.TrimPrefix(part, "<"))
			if v >= max {
				return false
			}
		}
	}
	return true
}

// normalizeVersion strips the leading 'v' and zero-pads each component
// for lexicographic comparison.
func normalizeVersion(v string) string {
	v = strings.TrimPrefix(v, "v")
	if v == "" {
		return ""
	}
	parts := strings.Split(v, ".")
	var normalized []string
	for _, p := range parts {
		// Check if it's numeric
		isNumeric := true
		for _, c := range p {
			if c < '0' || c > '9' {
				isNumeric = false
				break
			}
		}
		if !isNumeric {
			return "" // not a version string
		}
		for len(p) < 5 {
			p = "0" + p
		}
		normalized = append(normalized, p)
	}
	for len(normalized) < 3 {
		normalized = append(normalized, "00000")
	}
	return strings.Join(normalized, ".")
}

// --- Loading functions ---

func parseAdvisoryDB(data []byte) (*AdvisoryDB, error) {
	var db AdvisoryDB
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, fmt.Errorf("parsing advisory JSON: %w", err)
	}
	return &db, nil
}

func loadRemote(opts LoadOptions) (*AdvisoryDB, error) {
	client := &http.Client{Timeout: fetchTimeout}

	req, err := http.NewRequest("GET", remoteURL, nil)
	if err != nil {
		return nil, err
	}
	if opts.Token != "" {
		req.Header.Set("Authorization", "token "+opts.Token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB limit
	if err != nil {
		return nil, err
	}

	return parseAdvisoryDB(data)
}

func cacheDir() string {
	dir := os.Getenv("XDG_CACHE_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		dir = filepath.Join(home, ".cache")
	}
	return filepath.Join(dir, "abom")
}

func cachePath() string {
	dir := cacheDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "advisories.json")
}

func loadCache() (*AdvisoryDB, bool, error) {
	path := cachePath()
	if path == "" {
		return nil, false, fmt.Errorf("no cache path")
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, false, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}

	db, err := parseAdvisoryDB(data)
	if err != nil {
		return nil, false, err
	}

	fresh := time.Since(info.ModTime()) < cacheTTL
	return db, fresh, nil
}

func writeCache(db *AdvisoryDB) error {
	path := cachePath()
	if path == "" {
		return fmt.Errorf("no cache path")
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	data, err := json.Marshal(db)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0o600)
}
