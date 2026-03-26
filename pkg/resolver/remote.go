package resolver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/julietsecurity/abom/pkg/model"
	"github.com/julietsecurity/abom/pkg/parser"
)

// RemoteRepo represents a parsed GitHub repository reference.
type RemoteRepo struct {
	Owner string
	Repo  string
	Ref   string // branch/tag/sha, empty means default branch
}

// ParseRemoteTarget parses "github.com/owner/repo[@ref]" into a RemoteRepo.
// Returns nil if the target is not a remote reference.
func ParseRemoteTarget(target string) *RemoteRepo {
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")

	if !strings.HasPrefix(target, "github.com/") {
		return nil
	}

	path := strings.TrimPrefix(target, "github.com/")
	path = strings.TrimSuffix(path, "/")

	// Split ref from path
	var ref string
	if idx := strings.Index(path, "@"); idx != -1 {
		ref = path[idx+1:]
		path = path[:idx]
	}

	parts := strings.SplitN(path, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return nil
	}

	return &RemoteRepo{
		Owner: parts[0],
		Repo:  parts[1],
		Ref:   ref,
	}
}

// FetchRemoteWorkflows fetches workflow files from a GitHub repository via the API.
func FetchRemoteWorkflows(remote *RemoteRepo, token string, quiet bool) ([]*model.Workflow, string, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	ref := remote.Ref
	if ref == "" {
		// Get default branch
		defaultBranch, err := getDefaultBranch(client, remote, token)
		if err != nil {
			return nil, "", fmt.Errorf("getting default branch: %w", err)
		}
		ref = defaultBranch
	}

	// List files in .github/workflows/ using the Trees API
	treeURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/git/trees/%s?recursive=1",
		remote.Owner, remote.Repo, ref)

	body, err := apiRequest(client, treeURL, token)
	if err != nil {
		return nil, "", fmt.Errorf("listing repo tree: %w", err)
	}

	var tree struct {
		SHA  string `json:"sha"`
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"tree"`
	}
	if err := json.Unmarshal(body, &tree); err != nil {
		return nil, "", fmt.Errorf("parsing tree response: %w", err)
	}

	// Filter for workflow files
	var workflowPaths []string
	for _, entry := range tree.Tree {
		if entry.Type != "blob" {
			continue
		}
		if strings.HasPrefix(entry.Path, ".github/workflows/") &&
			(strings.HasSuffix(entry.Path, ".yml") || strings.HasSuffix(entry.Path, ".yaml")) {
			workflowPaths = append(workflowPaths, entry.Path)
		}
	}

	if len(workflowPaths) == 0 {
		return nil, "", fmt.Errorf("no workflow files found in %s/%s@%s", remote.Owner, remote.Repo, ref)
	}

	// Fetch and parse each workflow file
	fetcher := NewGitHubFetcher(token)
	var workflows []*model.Workflow

	for _, wfPath := range workflowPaths {
		content, err := fetcher.FetchWorkflowFile(remote.Owner, remote.Repo, ref, wfPath)
		if err != nil {
			if !quiet {
				fmt.Printf("Warning: skipping %s: %v\n", wfPath, err)
			}
			continue
		}

		wf, err := parser.ParseWorkflow(content, wfPath)
		if err != nil {
			if !quiet {
				fmt.Printf("Warning: skipping %s: %v\n", wfPath, err)
			}
			continue
		}
		wf.Path = wfPath
		workflows = append(workflows, wf)
	}

	return workflows, tree.SHA, nil
}

func getDefaultBranch(client *http.Client, remote *RemoteRepo, token string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s", remote.Owner, remote.Repo)

	body, err := apiRequest(client, url, token)
	if err != nil {
		return "", err
	}

	var repo struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := json.Unmarshal(body, &repo); err != nil {
		return "", fmt.Errorf("parsing repo response: %w", err)
	}

	if repo.DefaultBranch == "" {
		return "main", nil
	}

	return repo.DefaultBranch, nil
}

func apiRequest(client *http.Client, url, token string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	if token != "" {
		req.Header.Set("Authorization", "token "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate limited by GitHub — try using --github-token")
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("repository not found (or private — try --github-token)")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	return body, nil
}
