package resolver

import (
	"fmt"
	"net/http"
	"time"

	"github.com/julietsecurity/abom/pkg/model"
	"github.com/julietsecurity/abom/pkg/warnings"
)

// SHAVerifier verifies that a pinned commit SHA is reachable from a given
// repo's refs (and thus isn't an orphaned fork-only or force-pushed-away
// commit).
type SHAVerifier interface {
	// VerifyCommit returns (true, nil) if the SHA is reachable from owner/repo's
	// refs, (false, nil) if not found (404), and (false, err) for other
	// failures. Rate-limit responses should be returned as a distinct error so
	// callers can degrade gracefully.
	VerifyCommit(owner, repo, sha string) (exists bool, err error)
}

// ErrVerifyRateLimit is returned by verifiers when GitHub responds with 403
// or 429. Callers should treat this as "verification unavailable" rather than
// "SHA unreachable."
var ErrVerifyRateLimit = fmt.Errorf("rate limited")

// GitHubSHAVerifier calls the GitHub commits API to check whether a SHA is
// reachable from a repo's refs. Uses HEAD requests — cheaper than GET and
// the status code is all we need.
type GitHubSHAVerifier struct {
	client *http.Client
	token  string
}

func NewGitHubSHAVerifier(token string) *GitHubSHAVerifier {
	return &GitHubSHAVerifier{
		client: &http.Client{Timeout: 30 * time.Second},
		token:  token,
	}
}

func (v *GitHubSHAVerifier) VerifyCommit(owner, repo, sha string) (bool, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits/%s", owner, repo, sha)

	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	if v.token != "" {
		req.Header.Set("Authorization", "token "+v.token)
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound, http.StatusUnprocessableEntity:
		// 404: commit unknown to this repo; 422: SHA malformed or unreachable.
		return false, nil
	case http.StatusForbidden, http.StatusTooManyRequests:
		return false, ErrVerifyRateLimit
	default:
		return false, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
}

// VerifyABOMShas iterates the deduplicated action list produced by
// ABOM.CollectActions() and verifies each SHA-pinned reference. Results go
// into the collector; resolution behavior is unchanged.
//
// Dedup is keyed on owner/repo@sha so subdirectory variants of the same SHA
// don't cause redundant API calls.
//
// Once the verifier observes a rate-limit response, subsequent verifications
// are skipped for the remainder of the run to avoid stderr flooding.
func VerifyABOMShas(abom *model.ABOM, v SHAVerifier, col *warnings.Collector) {
	if abom == nil || v == nil || col == nil {
		return
	}

	seen := make(map[string]struct{})
	var rateLimited bool

	for _, ref := range abom.Actions {
		if ref.RefType != model.RefTypeSHA {
			continue
		}
		switch ref.ActionType {
		case model.ActionTypeDocker, model.ActionTypeLocal:
			continue
		}
		if ref.Owner == "" || ref.Repo == "" || ref.Ref == "" {
			continue
		}

		// Short SHAs (7–39 hex chars) can't be reliably verified — the commits
		// API accepts them but resolution is ambiguous on large repos.
		if len(ref.Ref) < 40 {
			key := fmt.Sprintf("%s/%s@%s", ref.Owner, ref.Repo, ref.Ref)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			col.Emit(warnings.Warning{
				Category: warnings.CategorySHAUnreachable,
				Subject:  subjectFor(ref),
				Message:  "short SHA cannot be reliably verified against upstream refs",
			})
			continue
		}

		key := fmt.Sprintf("%s/%s@%s", ref.Owner, ref.Repo, ref.Ref)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		if rateLimited {
			continue
		}

		exists, err := v.VerifyCommit(ref.Owner, ref.Repo, ref.Ref)
		if err != nil {
			if err == ErrVerifyRateLimit {
				rateLimited = true
				col.Emit(warnings.Warning{
					Category: warnings.CategoryRateLimit,
					Message:  "GitHub rate limit hit during SHA verification; remaining SHAs skipped",
					Err:      err,
				})
				continue
			}
			// Network / 5xx / other: advisory warning, NOT unreachable (avoids
			// false positives under flaky network).
			col.Emit(warnings.Warning{
				Category: warnings.CategoryRateLimit,
				Subject:  subjectFor(ref),
				Message:  "SHA verification failed (treat as advisory)",
				Err:      err,
			})
			continue
		}
		if !exists {
			col.Emit(warnings.Warning{
				Category: warnings.CategorySHAUnreachable,
				Subject:  subjectFor(ref),
				Message:  fmt.Sprintf("SHA not reachable from %s/%s refs (may be fork-only or force-pushed away)", ref.Owner, ref.Repo),
			})
		}
	}
}

func subjectFor(ref *model.ActionRef) string {
	if ref.Owner != "" && ref.Repo != "" && ref.Ref != "" {
		return fmt.Sprintf("%s/%s@%s", ref.Owner, ref.Repo, ref.Ref)
	}
	return ref.Raw
}
