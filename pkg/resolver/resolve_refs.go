package resolver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/julietsecurity/abom/pkg/model"
	"github.com/julietsecurity/abom/pkg/warnings"
)

// RefResolver resolves a tag or branch reference to the commit SHA it
// currently points to.
type RefResolver interface {
	// ResolveRef returns the commit SHA for owner/repo@ref. Returns an error
	// for network failures, 404, rate limiting, etc.
	ResolveRef(owner, repo, ref string) (sha string, err error)
}

// ErrResolveRateLimit signals that GitHub returned 403 or 429. Callers should
// stop issuing further resolve calls.
var ErrResolveRateLimit = fmt.Errorf("rate limited")

// GitHubRefResolver resolves refs via the GitHub commits API. The commits
// endpoint accepts tags, branches, and SHAs, and returns the resolved commit
// object, so one call handles all ref types.
type GitHubRefResolver struct {
	client *http.Client
	token  string
}

func NewGitHubRefResolver(token string) *GitHubRefResolver {
	return &GitHubRefResolver{
		client: &http.Client{Timeout: 30 * time.Second},
		token:  token,
	}
}

func (r *GitHubRefResolver) ResolveRef(owner, repo, ref string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits/%s", owner, repo, ref)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	if r.token != "" {
		req.Header.Set("Authorization", "token "+r.token)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// parse body
	case http.StatusNotFound, http.StatusUnprocessableEntity:
		return "", fmt.Errorf("ref not found")
	case http.StatusForbidden, http.StatusTooManyRequests:
		return "", ErrResolveRateLimit
	default:
		return "", fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}

	var payload struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("parsing commit response: %w", err)
	}
	if payload.SHA == "" {
		return "", fmt.Errorf("no sha in commit response")
	}
	return payload.SHA, nil
}

// ResolveABOMRefs iterates the deduplicated action list and resolves each
// tag- or branch-pinned reference to its current commit SHA. Stores the
// result in ActionRef.ResolvedSHA.
//
// Dedup is keyed on owner/repo@ref so subdirectory variants of the same
// action collapse into a single API call.
//
// Once the resolver observes a rate-limit response, subsequent resolutions
// are skipped for the remainder of the run.
func ResolveABOMRefs(abom *model.ABOM, r RefResolver, col *warnings.Collector) {
	if abom == nil || r == nil || col == nil {
		return
	}

	type cacheKey struct {
		owner, repo, ref string
	}
	cache := make(map[cacheKey]string)
	var rateLimited bool

	for _, ref := range abom.Actions {
		if ref.RefType != model.RefTypeTag && ref.RefType != model.RefTypeBranch {
			continue
		}
		switch ref.ActionType {
		case model.ActionTypeDocker, model.ActionTypeLocal:
			continue
		}
		if ref.Owner == "" || ref.Repo == "" || ref.Ref == "" {
			continue
		}

		key := cacheKey{ref.Owner, ref.Repo, ref.Ref}
		if sha, ok := cache[key]; ok {
			ref.ResolvedSHA = sha
			continue
		}

		if rateLimited {
			continue
		}

		sha, err := r.ResolveRef(ref.Owner, ref.Repo, ref.Ref)
		if err != nil {
			if err == ErrResolveRateLimit {
				rateLimited = true
				col.Emit(warnings.Warning{
					Category: warnings.CategoryRateLimit,
					Message:  "GitHub rate limit hit during ref resolution; remaining refs skipped",
					Err:      err,
				})
				continue
			}
			col.Emit(warnings.Warning{
				Category: warnings.CategoryRefResolve,
				Subject:  refResolveSubject(ref),
				Message:  "could not resolve ref to a commit SHA",
				Err:      err,
			})
			continue
		}

		cache[key] = sha
		ref.ResolvedSHA = sha
	}
}

func refResolveSubject(ref *model.ActionRef) string {
	if ref.Owner != "" && ref.Repo != "" && ref.Ref != "" {
		return fmt.Sprintf("%s/%s@%s", ref.Owner, ref.Repo, ref.Ref)
	}
	return ref.Raw
}
