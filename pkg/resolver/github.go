package resolver

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ContentFetcher fetches action and workflow files from GitHub.
type ContentFetcher interface {
	// FetchActionYAML fetches action.yml (or action.yaml) for an action.
	// path is the subdirectory within the repo (empty for root-level actions).
	FetchActionYAML(owner, repo, ref, path string) ([]byte, error)
	// FetchWorkflowFile fetches a reusable workflow file.
	FetchWorkflowFile(owner, repo, ref, path string) ([]byte, error)
}

// GitHubFetcher fetches files from raw.githubusercontent.com.
type GitHubFetcher struct {
	client  *http.Client
	token   string
	baseURL string
}

func NewGitHubFetcher(token string) *GitHubFetcher {
	return &GitHubFetcher{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		token:   token,
		baseURL: "https://raw.githubusercontent.com",
	}
}

func (f *GitHubFetcher) FetchActionYAML(owner, repo, ref, path string) ([]byte, error) {
	// Try action.yml first, then action.yaml
	prefix := fmt.Sprintf("%s/%s/%s/%s", owner, repo, ref, path)
	prefix = strings.TrimRight(prefix, "/")

	content, err := f.fetch(prefix + "/action.yml")
	if err == nil {
		return content, nil
	}

	content, err2 := f.fetch(prefix + "/action.yaml")
	if err2 == nil {
		return content, nil
	}

	return nil, fmt.Errorf("fetching action.yml/action.yaml for %s/%s@%s: %v", owner, repo, ref, err)
}

func (f *GitHubFetcher) FetchWorkflowFile(owner, repo, ref, path string) ([]byte, error) {
	filePath := fmt.Sprintf("%s/%s/%s/%s", owner, repo, ref, path)
	return f.fetch(filePath)
}

func (f *GitHubFetcher) fetch(path string) ([]byte, error) {
	url := f.baseURL + "/" + path

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if f.token != "" {
		req.Header.Set("Authorization", "token "+f.token)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("not found: %s", path)
	}

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate limited by GitHub — try using --github-token")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d for %s", resp.StatusCode, path)
	}

	// Limit response size to 10 MB to prevent OOM from malicious responses
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	return body, nil
}
