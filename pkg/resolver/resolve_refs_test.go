package resolver

import (
	"fmt"
	"testing"

	"github.com/julietsecurity/abom/pkg/model"
	"github.com/julietsecurity/abom/pkg/warnings"
)

// mockRefResolver returns canned SHAs keyed on owner/repo@ref.
type mockRefResolver struct {
	results map[string]string // owner/repo@ref -> sha or "" to signal 404
	calls   map[string]int
	err     error // global error (transport / rate limit)
}

func newMockRefResolver() *mockRefResolver {
	return &mockRefResolver{
		results: make(map[string]string),
		calls:   make(map[string]int),
	}
}

func (m *mockRefResolver) ResolveRef(owner, repo, ref string) (string, error) {
	key := fmt.Sprintf("%s/%s@%s", owner, repo, ref)
	m.calls[key]++
	if m.err != nil {
		return "", m.err
	}
	sha, ok := m.results[key]
	if !ok {
		return "", fmt.Errorf("ref not found")
	}
	return sha, nil
}

const resolvedSHA1 = "abcdef1234567890abcdef1234567890abcdef12"
const resolvedSHA2 = "0123456789abcdef0123456789abcdef01234567"

func newTagAction(owner, repo, path, tag string) *model.ActionRef {
	return &model.ActionRef{
		Owner:      owner,
		Repo:       repo,
		Path:       path,
		Ref:        tag,
		RefType:    model.RefTypeTag,
		ActionType: model.ActionTypeStandard,
	}
}

func newBranchAction(owner, repo, branch string) *model.ActionRef {
	return &model.ActionRef{
		Owner:      owner,
		Repo:       repo,
		Ref:        branch,
		RefType:    model.RefTypeBranch,
		ActionType: model.ActionTypeStandard,
	}
}

func TestResolveABOMRefs_Tag(t *testing.T) {
	m := newMockRefResolver()
	m.results["actions/checkout@v4"] = resolvedSHA1

	ref := newTagAction("actions", "checkout", "", "v4")
	abom := &model.ABOM{Actions: []*model.ActionRef{ref}}

	col := &warnings.Collector{}
	ResolveABOMRefs(abom, m, col)

	if ref.ResolvedSHA != resolvedSHA1 {
		t.Errorf("ResolvedSHA = %q, want %q", ref.ResolvedSHA, resolvedSHA1)
	}
	if col.Count() != 0 {
		t.Errorf("expected 0 warnings, got %d", col.Count())
	}
}

func TestResolveABOMRefs_Branch(t *testing.T) {
	m := newMockRefResolver()
	m.results["actions/checkout@main"] = resolvedSHA1

	ref := newBranchAction("actions", "checkout", "main")
	abom := &model.ABOM{Actions: []*model.ActionRef{ref}}

	col := &warnings.Collector{}
	ResolveABOMRefs(abom, m, col)

	if ref.ResolvedSHA != resolvedSHA1 {
		t.Errorf("ResolvedSHA = %q, want %q", ref.ResolvedSHA, resolvedSHA1)
	}
}

func TestResolveABOMRefs_SHASkipped(t *testing.T) {
	m := newMockRefResolver()

	ref := &model.ActionRef{
		Owner:      "actions",
		Repo:       "checkout",
		Ref:        resolvedSHA1,
		RefType:    model.RefTypeSHA,
		ActionType: model.ActionTypeStandard,
	}
	abom := &model.ABOM{Actions: []*model.ActionRef{ref}}

	col := &warnings.Collector{}
	ResolveABOMRefs(abom, m, col)

	if len(m.calls) != 0 {
		t.Errorf("expected no API calls for SHA ref, got %d", len(m.calls))
	}
	if ref.ResolvedSHA != "" {
		t.Errorf("SHA ref should not have ResolvedSHA set, got %q", ref.ResolvedSHA)
	}
}

func TestResolveABOMRefs_DockerAndLocal_Skipped(t *testing.T) {
	m := newMockRefResolver()

	docker := &model.ActionRef{
		Raw:        "docker://alpine:3.18",
		RefType:    model.RefTypeTag,
		ActionType: model.ActionTypeDocker,
	}
	local := &model.ActionRef{
		Raw:        "./local-action",
		RefType:    model.RefTypeTag,
		ActionType: model.ActionTypeLocal,
	}
	abom := &model.ABOM{Actions: []*model.ActionRef{docker, local}}

	col := &warnings.Collector{}
	ResolveABOMRefs(abom, m, col)

	if len(m.calls) != 0 {
		t.Errorf("expected no API calls for docker/local, got %d", len(m.calls))
	}
}

func TestResolveABOMRefs_Dedup(t *testing.T) {
	m := newMockRefResolver()
	m.results["actions/checkout@v4"] = resolvedSHA1

	a := newTagAction("actions", "checkout", "", "v4")
	b := newTagAction("actions", "checkout", "sub", "v4")
	b.ActionType = model.ActionTypeSubdirectory

	abom := &model.ABOM{Actions: []*model.ActionRef{a, b}}
	col := &warnings.Collector{}
	ResolveABOMRefs(abom, m, col)

	if m.calls["actions/checkout@v4"] != 1 {
		t.Errorf("expected 1 API call, got %d", m.calls["actions/checkout@v4"])
	}
	if a.ResolvedSHA != resolvedSHA1 || b.ResolvedSHA != resolvedSHA1 {
		t.Errorf("both refs should share resolved SHA: a=%q b=%q", a.ResolvedSHA, b.ResolvedSHA)
	}
}

func TestResolveABOMRefs_RefNotFound_Warning(t *testing.T) {
	m := newMockRefResolver()
	// No entry for this ref, mockRefResolver returns "ref not found" error

	ref := newTagAction("actions", "checkout", "", "v999")
	abom := &model.ABOM{Actions: []*model.ActionRef{ref}}

	col := &warnings.Collector{}
	ResolveABOMRefs(abom, m, col)

	if col.Count() != 1 {
		t.Fatalf("expected 1 warning, got %d", col.Count())
	}
	w := col.All()[0]
	if w.Category != warnings.CategoryRefResolve {
		t.Errorf("expected RefResolve, got %s", w.Category)
	}
	if ref.ResolvedSHA != "" {
		t.Errorf("failed resolve should leave ResolvedSHA empty, got %q", ref.ResolvedSHA)
	}
}

func TestResolveABOMRefs_TransportError_RefResolveCategory(t *testing.T) {
	m := newMockRefResolver()
	m.err = fmt.Errorf("network unreachable")

	ref := newTagAction("actions", "checkout", "", "v4")
	abom := &model.ABOM{Actions: []*model.ActionRef{ref}}

	col := &warnings.Collector{}
	ResolveABOMRefs(abom, m, col)

	if col.Count() != 1 {
		t.Fatalf("expected 1 warning, got %d", col.Count())
	}
	w := col.All()[0]
	if w.Category != warnings.CategoryRefResolve {
		t.Errorf("expected RefResolve for transport error, got %s", w.Category)
	}
}

func TestResolveABOMRefs_MidRunRateLimit(t *testing.T) {
	m := newMockRefResolver()
	m.results["a/b@v1"] = resolvedSHA1
	// c/d@v1 will hit rate limit via global err triggered partway through.
	// Since we can't easily toggle global err mid-iteration, simulate by
	// returning ErrResolveRateLimit from the second call onward.

	// Simpler approach: use a dedicated rate-limit resolver
	var callCount int
	rl := rateLimitOnCallN{
		results: m.results,
		n:       2, // rate-limit on 2nd call
		count:   &callCount,
	}

	abom := &model.ABOM{
		Actions: []*model.ActionRef{
			newTagAction("a", "b", "", "v1"),
			newTagAction("c", "d", "", "v1"),
			newTagAction("e", "f", "", "v1"),
		},
	}
	col := &warnings.Collector{}
	ResolveABOMRefs(abom, rl, col)

	// Expect exactly one rate-limit warning for c/d, and e/f skipped.
	if col.Count() != 1 {
		t.Fatalf("expected 1 warning, got %d: %+v", col.Count(), col.All())
	}
	if col.All()[0].Category != warnings.CategoryRateLimit {
		t.Errorf("expected RateLimit, got %s", col.All()[0].Category)
	}
	if callCount != 2 {
		t.Errorf("expected 2 calls before skip, got %d", callCount)
	}
	if abom.Actions[0].ResolvedSHA != resolvedSHA1 {
		t.Errorf("first ref should have been resolved, got %q", abom.Actions[0].ResolvedSHA)
	}
	if abom.Actions[2].ResolvedSHA != "" {
		t.Errorf("third ref should be skipped, got %q", abom.Actions[2].ResolvedSHA)
	}
}

type rateLimitOnCallN struct {
	results map[string]string
	n       int
	count   *int
}

func (r rateLimitOnCallN) ResolveRef(owner, repo, ref string) (string, error) {
	*r.count++
	if *r.count == r.n {
		return "", ErrResolveRateLimit
	}
	key := fmt.Sprintf("%s/%s@%s", owner, repo, ref)
	if sha, ok := r.results[key]; ok {
		return sha, nil
	}
	return resolvedSHA2, nil
}

func TestResolveABOMRefs_NilCollector_NoPanic(t *testing.T) {
	m := newMockRefResolver()
	abom := &model.ABOM{Actions: []*model.ActionRef{newTagAction("a", "b", "", "v1")}}
	ResolveABOMRefs(abom, m, nil)
}
