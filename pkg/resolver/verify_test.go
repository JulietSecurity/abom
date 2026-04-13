package resolver

import (
	"fmt"
	"strings"
	"testing"

	"github.com/julietsecurity/abom/pkg/model"
	"github.com/julietsecurity/abom/pkg/warnings"
)

// mockVerifier records calls and returns canned outcomes per SHA.
type mockVerifier struct {
	// Keyed on "owner/repo@sha". Value of 200/404/-1 (rate limit).
	responses map[string]int
	calls     map[string]int
	err       error // global error (transport)
}

func newMockVerifier() *mockVerifier {
	return &mockVerifier{
		responses: make(map[string]int),
		calls:     make(map[string]int),
	}
}

func (m *mockVerifier) VerifyCommit(owner, repo, sha string) (bool, error) {
	key := fmt.Sprintf("%s/%s@%s", owner, repo, sha)
	m.calls[key]++
	if m.err != nil {
		return false, m.err
	}
	code, ok := m.responses[key]
	if !ok {
		// Default to 200 if not configured
		return true, nil
	}
	switch code {
	case 200:
		return true, nil
	case 404:
		return false, nil
	case -1:
		return false, ErrVerifyRateLimit
	default:
		return false, fmt.Errorf("mock error code %d", code)
	}
}

const fullSHA1 = "abcdef1234567890abcdef1234567890abcdef12"
const fullSHA2 = "0123456789abcdef0123456789abcdef01234567"
const fullSHA3 = "fedcba0987654321fedcba0987654321fedcba09"

func newSHAAction(owner, repo, path, sha string) *model.ActionRef {
	raw := owner + "/" + repo
	if path != "" {
		raw += "/" + path
	}
	raw += "@" + sha
	return &model.ActionRef{
		Raw:        raw,
		Owner:      owner,
		Repo:       repo,
		Path:       path,
		Ref:        sha,
		RefType:    model.RefTypeSHA,
		ActionType: model.ActionTypeStandard,
	}
}

func TestVerify_ReachableSHA_NoWarning(t *testing.T) {
	mv := newMockVerifier()
	mv.responses[fmt.Sprintf("actions/checkout@%s", fullSHA1)] = 200

	abom := &model.ABOM{
		Actions: []*model.ActionRef{newSHAAction("actions", "checkout", "", fullSHA1)},
	}

	col := &warnings.Collector{}
	VerifyABOMShas(abom, mv, col)

	if col.Count() != 0 {
		t.Errorf("expected 0 warnings, got %d: %+v", col.Count(), col.All())
	}
}

func TestVerify_UnreachableSHA_Warning(t *testing.T) {
	mv := newMockVerifier()
	mv.responses[fmt.Sprintf("actions/checkout@%s", fullSHA1)] = 404

	abom := &model.ABOM{
		Actions: []*model.ActionRef{newSHAAction("actions", "checkout", "", fullSHA1)},
	}

	col := &warnings.Collector{}
	VerifyABOMShas(abom, mv, col)

	if col.Count() != 1 {
		t.Fatalf("expected 1 warning, got %d", col.Count())
	}
	w := col.All()[0]
	if w.Category != warnings.CategorySHAUnreachable {
		t.Errorf("expected SHAUnreachable, got %s", w.Category)
	}
	if !strings.Contains(w.Subject, fullSHA1) {
		t.Errorf("expected subject to contain SHA, got %q", w.Subject)
	}
}

func TestVerify_DedupSameSHA_OneCall(t *testing.T) {
	mv := newMockVerifier()
	mv.responses[fmt.Sprintf("actions/checkout@%s", fullSHA1)] = 200

	// Same SHA, two different raw refs (one as standard, one as subdirectory).
	a := newSHAAction("actions", "checkout", "", fullSHA1)
	b := newSHAAction("actions", "checkout", "sub", fullSHA1)
	b.ActionType = model.ActionTypeSubdirectory

	abom := &model.ABOM{Actions: []*model.ActionRef{a, b}}
	col := &warnings.Collector{}
	VerifyABOMShas(abom, mv, col)

	key := fmt.Sprintf("actions/checkout@%s", fullSHA1)
	if mv.calls[key] != 1 {
		t.Errorf("expected 1 API call, got %d", mv.calls[key])
	}
	if col.Count() != 0 {
		t.Errorf("expected 0 warnings, got %d", col.Count())
	}
}

func TestVerify_NonSHARef_Skipped(t *testing.T) {
	mv := newMockVerifier()

	ref := &model.ActionRef{
		Raw:        "actions/checkout@v4",
		Owner:      "actions",
		Repo:       "checkout",
		Ref:        "v4",
		RefType:    model.RefTypeTag,
		ActionType: model.ActionTypeStandard,
	}
	abom := &model.ABOM{Actions: []*model.ActionRef{ref}}

	col := &warnings.Collector{}
	VerifyABOMShas(abom, mv, col)

	if len(mv.calls) != 0 {
		t.Errorf("expected no API calls for non-SHA ref, got %d", len(mv.calls))
	}
	if col.Count() != 0 {
		t.Errorf("expected 0 warnings, got %d", col.Count())
	}
}

func TestVerify_DockerAndLocal_Skipped(t *testing.T) {
	mv := newMockVerifier()

	docker := &model.ActionRef{
		Raw:        "docker://alpine:3.18",
		RefType:    model.RefTypeSHA, // intentionally set to SHA to prove action type filter runs
		ActionType: model.ActionTypeDocker,
	}
	local := &model.ActionRef{
		Raw:        "./local-action",
		RefType:    model.RefTypeSHA,
		ActionType: model.ActionTypeLocal,
	}
	abom := &model.ABOM{Actions: []*model.ActionRef{docker, local}}

	col := &warnings.Collector{}
	VerifyABOMShas(abom, mv, col)

	if len(mv.calls) != 0 {
		t.Errorf("expected no API calls for docker/local, got %d", len(mv.calls))
	}
	if col.Count() != 0 {
		t.Errorf("expected 0 warnings, got %d", col.Count())
	}
}

func TestVerify_ShortSHA_WarnWithoutAPICall(t *testing.T) {
	mv := newMockVerifier()

	short := "abcdef1" // 7 chars
	ref := newSHAAction("actions", "checkout", "", short)

	abom := &model.ABOM{Actions: []*model.ActionRef{ref}}
	col := &warnings.Collector{}
	VerifyABOMShas(abom, mv, col)

	if len(mv.calls) != 0 {
		t.Errorf("expected no API calls for short SHA, got %d", len(mv.calls))
	}
	if col.Count() != 1 {
		t.Fatalf("expected 1 warning, got %d", col.Count())
	}
	w := col.All()[0]
	if w.Category != warnings.CategorySHAUnreachable {
		t.Errorf("expected SHAUnreachable, got %s", w.Category)
	}
	if !strings.Contains(w.Message, "short SHA") {
		t.Errorf("expected short SHA message, got %q", w.Message)
	}
}

func TestVerify_TransportError_RateLimitCategory(t *testing.T) {
	mv := newMockVerifier()
	mv.err = fmt.Errorf("network unreachable")

	abom := &model.ABOM{
		Actions: []*model.ActionRef{newSHAAction("actions", "checkout", "", fullSHA1)},
	}
	col := &warnings.Collector{}
	VerifyABOMShas(abom, mv, col)

	if col.Count() != 1 {
		t.Fatalf("expected 1 warning, got %d", col.Count())
	}
	w := col.All()[0]
	if w.Category != warnings.CategoryRateLimit {
		t.Errorf("expected RateLimit (for transport errors), got %s", w.Category)
	}
}

func TestVerify_MidRunRateLimit_OneWarningOnly(t *testing.T) {
	mv := newMockVerifier()
	// First SHA succeeds; second hits rate limit; third would 200 but should be
	// skipped because rateLimited flag is set.
	mv.responses[fmt.Sprintf("a/b@%s", fullSHA1)] = 200
	mv.responses[fmt.Sprintf("c/d@%s", fullSHA2)] = -1
	mv.responses[fmt.Sprintf("e/f@%s", fullSHA3)] = 200

	abom := &model.ABOM{
		Actions: []*model.ActionRef{
			newSHAAction("a", "b", "", fullSHA1),
			newSHAAction("c", "d", "", fullSHA2),
			newSHAAction("e", "f", "", fullSHA3),
		},
	}
	col := &warnings.Collector{}
	VerifyABOMShas(abom, mv, col)

	// Exactly one rate-limit warning (for the c/d request).
	if col.Count() != 1 {
		t.Fatalf("expected 1 warning, got %d: %+v", col.Count(), col.All())
	}
	if col.All()[0].Category != warnings.CategoryRateLimit {
		t.Errorf("expected RateLimit, got %s", col.All()[0].Category)
	}

	// e/f should not have been called.
	if mv.calls[fmt.Sprintf("e/f@%s", fullSHA3)] != 0 {
		t.Errorf("e/f should be skipped after rate limit, but was called")
	}
	// a/b and c/d should have each been called once.
	if mv.calls[fmt.Sprintf("a/b@%s", fullSHA1)] != 1 {
		t.Errorf("a/b should be called once, got %d", mv.calls[fmt.Sprintf("a/b@%s", fullSHA1)])
	}
	if mv.calls[fmt.Sprintf("c/d@%s", fullSHA2)] != 1 {
		t.Errorf("c/d should be called once, got %d", mv.calls[fmt.Sprintf("c/d@%s", fullSHA2)])
	}
}

func TestVerify_NilCollector_NoPanic(t *testing.T) {
	mv := newMockVerifier()
	abom := &model.ABOM{Actions: []*model.ActionRef{newSHAAction("a", "b", "", fullSHA1)}}
	// Should not panic.
	VerifyABOMShas(abom, mv, nil)
}
