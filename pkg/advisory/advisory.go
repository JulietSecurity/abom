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
	remoteURL    = "https://raw.githubusercontent.com/JulietSecurity/abom-advisories/main/db/advisories.json"
	cacheTTL     = 1 * time.Hour
	fetchTimeout = 5 * time.Second

	ecosystemGitHubActions = "GitHub Actions"
)

// AdvisoryDB is the top-level structure for the advisory database file.
// Individual advisories conform to the OSV schema (https://ossf.github.io/osv-schema/).
type AdvisoryDB struct {
	LastUpdated string     `json:"last_updated"`
	Advisories  []Advisory `json:"advisories"`
}

// Advisory is an OSV-shaped advisory entry with ABOM extensions.
type Advisory struct {
	SchemaVersion    string              `json:"schema_version"`
	ID               string              `json:"id"`
	Modified         string              `json:"modified"`
	Published        string              `json:"published,omitempty"`
	Withdrawn        string              `json:"withdrawn,omitempty"`
	Aliases          []string            `json:"aliases,omitempty"`
	Summary          string              `json:"summary,omitempty"`
	Details          string              `json:"details,omitempty"`
	Severity         []Severity          `json:"severity,omitempty"`
	Affected         []Affected          `json:"affected"`
	References       []Reference         `json:"references,omitempty"`
	DatabaseSpecific DatabaseSpecific    `json:"database_specific,omitempty"`
}

// Severity follows OSV's severity shape. For CVSS_V3 / CVSS_V4, Score is the
// full vector string.
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Affected describes a single affected package within an advisory.
type Affected struct {
	Package           Package           `json:"package"`
	Ranges            []Range           `json:"ranges,omitempty"`
	Versions          []string          `json:"versions,omitempty"`
	EcosystemSpecific EcosystemSpecific `json:"ecosystem_specific,omitempty"`
}

// Package identifies the affected artifact.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// Range describes an affected version range via a sequence of events.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Event is a single point in a range's timeline. Exactly one of the fields
// below is set per event.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// Reference is a typed URL, per the OSV references spec.
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// EcosystemSpecific holds per-package, ecosystem-scoped extensions.
type EcosystemSpecific struct {
	ABOM *ABOMEcosystemFields `json:"abom,omitempty"`
}

// ABOMEcosystemFields are GitHub-Actions-specific ABOM extensions.
type ABOMEcosystemFields struct {
	ToolNames      []string        `json:"tool_names,omitempty"`
	AffectedPeriod *AffectedPeriod `json:"affected_period,omitempty"`
}

// AffectedPeriod is an incident time window. The To field is intentionally
// string (not *string) — an empty string denotes an ongoing incident.
type AffectedPeriod struct {
	From string `json:"from"`
	To   string `json:"to,omitempty"`
}

// DatabaseSpecific holds advisory-wide, database-scoped extensions.
type DatabaseSpecific struct {
	ABOM *ABOMDatabaseFields `json:"abom,omitempty"`
}

// ABOMDatabaseFields are ABOM-wide extensions to the OSV schema.
type ABOMDatabaseFields struct {
	Indicators         *Indicators `json:"indicators,omitempty"`
	RecommendedActions []string    `json:"recommended_actions,omitempty"`
}

// Indicators contains IOCs for an advisory.
type Indicators struct {
	DockerImages []string `json:"docker_images,omitempty"`
	ReposToCheck []string `json:"repos_to_check,omitempty"`
	Notes        string   `json:"notes,omitempty"`
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
	if !opts.Offline {
		if db, err := loadRemote(opts); err == nil {
			if !opts.NoCache {
				_ = writeCache(db)
			}
			return &Database{db: *db, source: "remote"}
		}
	}

	if !opts.NoCache && !opts.Offline {
		if db, fresh, err := loadCache(); err == nil {
			if !fresh && !opts.Quiet {
				fmt.Fprintf(os.Stderr, "Warning: using cached advisory data from %s. Run with network access for latest advisories.\n", db.LastUpdated)
			}
			return &Database{db: *db, source: "cache"}
		}
	}

	db, _ := parseAdvisoryDB(builtinData)
	if !opts.Offline && !opts.Quiet {
		fmt.Fprintf(os.Stderr, "Warning: using built-in advisory data from %s. Run with network access for latest advisories.\n", db.LastUpdated)
	}
	return &Database{db: *db, source: "builtin"}
}

// Check returns the first matching advisory for an action ref, along with a
// match reason: "compromised" (version in affected range), "verify-sha"
// (SHA-pinned and can't be version-compared), or "detected-tool" (matched via
// wrapper detection / IoC).
func (d *Database) Check(ref *model.ActionRef) (*Advisory, string) {
	for i := range d.db.Advisories {
		adv := &d.db.Advisories[i]
		if adv.Withdrawn != "" {
			continue
		}

		for _, aff := range adv.Affected {
			if result := matchAffected(ref, &aff); result != "" {
				return adv, result
			}
		}

		if ref.ActionType == model.ActionTypeDocker && adv.DatabaseSpecific.ABOM != nil && adv.DatabaseSpecific.ABOM.Indicators != nil {
			ind := adv.DatabaseSpecific.ABOM.Indicators
			for _, img := range ind.DockerImages {
				if strings.HasPrefix(ref.Path, img) || strings.HasPrefix(ref.Path, strings.Split(img, ":")[0]) {
					return adv, "compromised"
				}
			}
		}

		if len(ref.DetectedTools) > 0 {
			for _, aff := range adv.Affected {
				if aff.Package.Ecosystem != ecosystemGitHubActions {
					continue
				}
				var toolNames []string
				if aff.EcosystemSpecific.ABOM != nil {
					toolNames = aff.EcosystemSpecific.ABOM.ToolNames
				}
				if len(toolNames) == 0 {
					toolNames = inferToolNames(aff.Package.Name)
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

// matchAffected checks if an ActionRef matches an Affected entry.
func matchAffected(ref *model.ActionRef, aff *Affected) string {
	if aff.Package.Ecosystem != ecosystemGitHubActions {
		return ""
	}

	parts := strings.SplitN(aff.Package.Name, "/", 2)
	if len(parts) != 2 {
		return ""
	}
	owner, repo := parts[0], parts[1]

	if !strings.EqualFold(ref.Owner, owner) || !strings.EqualFold(ref.Repo, repo) {
		return ""
	}

	// SHA-pinned refs can't be ordinally compared against tag ranges.
	// Flag as "verify manually" so users know to check against the
	// affected_period or upstream history.
	if ref.RefType == model.RefTypeSHA {
		return "verify-sha"
	}

	// Explicit version list (if present) is a direct equality check.
	for _, v := range aff.Versions {
		if ref.Ref == v {
			return "compromised"
		}
	}

	// Walk ranges. Any match means the ref is affected.
	for i := range aff.Ranges {
		if matchesRange(ref.Ref, &aff.Ranges[i]) {
			return "compromised"
		}
	}

	return ""
}

// matchesRange walks events in declaration order and toggles affected state.
// Each introduced starts an affected window; each fixed or last_affected
// closes it. Returns true if version lands inside any affected window.
func matchesRange(version string, rng *Range) bool {
	if rng.Type != "ECOSYSTEM" && rng.Type != "SEMVER" {
		return false
	}

	affected := false
	for _, ev := range rng.Events {
		switch {
		case ev.Introduced != "":
			// "0" is the OSV sentinel meaning "from the beginning of time."
			if ev.Introduced == "0" {
				affected = true
			} else if compareVersions(version, ev.Introduced) >= 0 {
				affected = true
			}
		case ev.Fixed != "":
			if compareVersions(version, ev.Fixed) >= 0 {
				affected = false
			}
		case ev.LastAffected != "":
			if compareVersions(version, ev.LastAffected) > 0 {
				affected = false
			}
		}
	}
	return affected
}

// compareVersions compares two tag-like version strings. Returns -1, 0, or 1.
// Only works for semver-shaped strings (optionally v-prefixed). Non-numeric
// strings (e.g. "main") compare as less than any valid version.
func compareVersions(a, b string) int {
	an := normalizeVersion(a)
	bn := normalizeVersion(b)
	switch {
	case an == "" && bn == "":
		return 0
	case an == "":
		return -1
	case bn == "":
		return 1
	case an < bn:
		return -1
	case an > bn:
		return 1
	}
	return 0
}

// normalizeVersion strips the leading 'v' and zero-pads each component for
// lexicographic comparison. Returns "" for non-numeric strings.
func normalizeVersion(v string) string {
	v = strings.TrimPrefix(v, "v")
	if v == "" {
		return ""
	}
	parts := strings.Split(v, ".")
	var normalized []string
	for _, p := range parts {
		for _, c := range p {
			if c < '0' || c > '9' {
				return ""
			}
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

// inferToolNames extracts likely tool names from an action package name.
// e.g., "aquasecurity/trivy-action" -> ["trivy"]
// e.g., "aquasecurity/setup-trivy" -> ["trivy"]
func inferToolNames(pkgName string) []string {
	parts := strings.SplitN(pkgName, "/", 2)
	if len(parts) != 2 {
		return nil
	}
	repo := strings.ToLower(parts[1])

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

	knownTools := []string{"trivy", "grype", "snyk", "cosign", "syft"}

	var tools []string
	for _, candidate := range candidates {
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

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
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
