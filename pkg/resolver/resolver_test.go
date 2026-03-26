package resolver

import (
	"fmt"
	"testing"

	"github.com/julietsecurity/abom/pkg/model"
)

// mockFetcher returns pre-loaded content for testing.
type mockFetcher struct {
	files map[string][]byte // key: "owner/repo/ref/path"
}

func (m *mockFetcher) FetchActionYAML(owner, repo, ref, path string) ([]byte, error) {
	key := fmt.Sprintf("%s/%s/%s/%s/action.yml", owner, repo, ref, path)
	if content, ok := m.files[key]; ok {
		return content, nil
	}
	// Try without trailing path
	key = fmt.Sprintf("%s/%s/%s/action.yml", owner, repo, ref)
	if content, ok := m.files[key]; ok {
		return content, nil
	}
	return nil, fmt.Errorf("not found: %s/%s@%s path=%s", owner, repo, ref, path)
}

func (m *mockFetcher) FetchWorkflowFile(owner, repo, ref, path string) ([]byte, error) {
	key := fmt.Sprintf("%s/%s/%s/%s", owner, repo, ref, path)
	if content, ok := m.files[key]; ok {
		return content, nil
	}
	return nil, fmt.Errorf("not found: %s/%s@%s path=%s", owner, repo, ref, path)
}

func TestResolve_NoDeps(t *testing.T) {
	mock := &mockFetcher{
		files: map[string][]byte{
			"actions/checkout/v4/action.yml": []byte(`name: Checkout
runs:
  using: node20
  main: index.js
`),
		},
	}

	r := &Resolver{
		fetcher: mock,
		opts:    Options{MaxDepth: 10},
		seen:    make(map[string]bool),
		memo:    make(map[string][]*model.ActionRef),
	}

	ref := &model.ActionRef{
		Raw:        "actions/checkout@v4",
		Owner:      "actions",
		Repo:       "checkout",
		Ref:        "v4",
		ActionType: model.ActionTypeStandard,
	}

	r.resolveAction(ref, 0)

	if ref.ResolveError != "" {
		t.Errorf("unexpected error: %s", ref.ResolveError)
	}
	if len(ref.Dependencies) != 0 {
		t.Errorf("expected 0 deps, got %d", len(ref.Dependencies))
	}
}

func TestResolve_OneLevelTransitive(t *testing.T) {
	mock := &mockFetcher{
		files: map[string][]byte{
			"org/composite/v1/action.yml": []byte(`name: My Composite
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-go@v5
`),
			"actions/checkout/v4/action.yml": []byte(`name: Checkout
runs:
  using: node20
  main: index.js
`),
			"actions/setup-go/v5/action.yml": []byte(`name: Setup Go
runs:
  using: node20
  main: index.js
`),
		},
	}

	r := &Resolver{
		fetcher: mock,
		opts:    Options{MaxDepth: 10, Quiet: true},
		seen:    make(map[string]bool),
		memo:    make(map[string][]*model.ActionRef),
	}

	ref := &model.ActionRef{
		Raw:        "org/composite@v1",
		Owner:      "org",
		Repo:       "composite",
		Ref:        "v1",
		ActionType: model.ActionTypeStandard,
	}

	r.resolveAction(ref, 0)

	if ref.ResolveError != "" {
		t.Errorf("unexpected error: %s", ref.ResolveError)
	}
	if len(ref.Dependencies) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(ref.Dependencies))
	}
	if ref.Dependencies[0].Owner != "actions" || ref.Dependencies[0].Repo != "checkout" {
		t.Errorf("dep 0 = %s/%s, want actions/checkout", ref.Dependencies[0].Owner, ref.Dependencies[0].Repo)
	}
	if ref.Dependencies[1].Owner != "actions" || ref.Dependencies[1].Repo != "setup-go" {
		t.Errorf("dep 1 = %s/%s, want actions/setup-go", ref.Dependencies[1].Owner, ref.Dependencies[1].Repo)
	}
}

func TestResolve_MultiLevelTransitive(t *testing.T) {
	mock := &mockFetcher{
		files: map[string][]byte{
			"org/action-a/v1/action.yml": []byte(`name: A
runs:
  using: composite
  steps:
    - uses: org/action-b@v1
`),
			"org/action-b/v1/action.yml": []byte(`name: B
runs:
  using: composite
  steps:
    - uses: org/action-c@v1
`),
			"org/action-c/v1/action.yml": []byte(`name: C
runs:
  using: node20
  main: index.js
`),
		},
	}

	r := &Resolver{
		fetcher: mock,
		opts:    Options{MaxDepth: 10, Quiet: true},
		seen:    make(map[string]bool),
		memo:    make(map[string][]*model.ActionRef),
	}

	ref := &model.ActionRef{
		Raw:        "org/action-a@v1",
		Owner:      "org",
		Repo:       "action-a",
		Ref:        "v1",
		ActionType: model.ActionTypeStandard,
	}

	r.resolveAction(ref, 0)

	if ref.ResolveError != "" {
		t.Errorf("unexpected error: %s", ref.ResolveError)
	}
	if len(ref.Dependencies) != 1 {
		t.Fatalf("A: expected 1 dep, got %d", len(ref.Dependencies))
	}

	depB := ref.Dependencies[0]
	if depB.Owner != "org" || depB.Repo != "action-b" {
		t.Errorf("A dep = %s/%s, want org/action-b", depB.Owner, depB.Repo)
	}
	if len(depB.Dependencies) != 1 {
		t.Fatalf("B: expected 1 dep, got %d", len(depB.Dependencies))
	}

	depC := depB.Dependencies[0]
	if depC.Owner != "org" || depC.Repo != "action-c" {
		t.Errorf("B dep = %s/%s, want org/action-c", depC.Owner, depC.Repo)
	}
}

func TestResolve_CycleDetection(t *testing.T) {
	mock := &mockFetcher{
		files: map[string][]byte{
			"org/action-a/v1/action.yml": []byte(`name: A
runs:
  using: composite
  steps:
    - uses: org/action-b@v1
`),
			"org/action-b/v1/action.yml": []byte(`name: B
runs:
  using: composite
  steps:
    - uses: org/action-a@v1
`),
		},
	}

	r := &Resolver{
		fetcher: mock,
		opts:    Options{MaxDepth: 10, Quiet: true},
		seen:    make(map[string]bool),
		memo:    make(map[string][]*model.ActionRef),
	}

	ref := &model.ActionRef{
		Raw:        "org/action-a@v1",
		Owner:      "org",
		Repo:       "action-a",
		Ref:        "v1",
		ActionType: model.ActionTypeStandard,
	}

	r.resolveAction(ref, 0)

	// A should resolve to B, but B -> A should detect the cycle
	if len(ref.Dependencies) != 1 {
		t.Fatalf("A: expected 1 dep, got %d", len(ref.Dependencies))
	}

	depB := ref.Dependencies[0]
	if len(depB.Dependencies) != 1 {
		t.Fatalf("B: expected 1 dep, got %d", len(depB.Dependencies))
	}

	cycleRef := depB.Dependencies[0]
	if cycleRef.ResolveError != "cycle detected" {
		t.Errorf("expected cycle detected error, got %q", cycleRef.ResolveError)
	}
}

func TestResolve_DepthLimit(t *testing.T) {
	mock := &mockFetcher{
		files: map[string][]byte{
			"org/deep/v1/action.yml": []byte(`name: Deep
runs:
  using: composite
  steps:
    - uses: org/deeper@v1
`),
			"org/deeper/v1/action.yml": []byte(`name: Deeper
runs:
  using: node20
  main: index.js
`),
		},
	}

	r := &Resolver{
		fetcher: mock,
		opts:    Options{MaxDepth: 1, Quiet: true},
		seen:    make(map[string]bool),
		memo:    make(map[string][]*model.ActionRef),
	}

	ref := &model.ActionRef{
		Raw:        "org/deep@v1",
		Owner:      "org",
		Repo:       "deep",
		Ref:        "v1",
		ActionType: model.ActionTypeStandard,
	}

	r.resolveAction(ref, 0)

	// Should resolve one level (depth 0 -> 1), but the dep at depth 1 should hit limit
	if len(ref.Dependencies) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(ref.Dependencies))
	}

	dep := ref.Dependencies[0]
	if dep.ResolveError == "" {
		t.Error("expected depth limit error on nested dep")
	}
}

func TestResolve_FetchError(t *testing.T) {
	mock := &mockFetcher{
		files: map[string][]byte{}, // empty — everything will 404
	}

	r := &Resolver{
		fetcher: mock,
		opts:    Options{MaxDepth: 10, Quiet: true},
		seen:    make(map[string]bool),
		memo:    make(map[string][]*model.ActionRef),
	}

	ref := &model.ActionRef{
		Raw:        "missing/action@v1",
		Owner:      "missing",
		Repo:       "action",
		Ref:        "v1",
		ActionType: model.ActionTypeStandard,
	}

	r.resolveAction(ref, 0)

	if ref.ResolveError == "" {
		t.Error("expected error for missing action")
	}
}

func TestResolve_DockerSkipped(t *testing.T) {
	r := &Resolver{
		opts: Options{MaxDepth: 10, Quiet: true},
		seen: make(map[string]bool),
		memo: make(map[string][]*model.ActionRef),
	}

	ref := &model.ActionRef{
		Raw:        "docker://alpine:3.18",
		ActionType: model.ActionTypeDocker,
		Path:       "alpine:3.18",
	}

	r.resolveAction(ref, 0)

	if ref.ResolveError != "" {
		t.Errorf("docker action should not error: %s", ref.ResolveError)
	}
	if len(ref.Dependencies) != 0 {
		t.Errorf("docker action should have no deps")
	}
}

func TestResolve_ReusableWorkflow(t *testing.T) {
	mock := &mockFetcher{
		files: map[string][]byte{
			"org/repo/main/.github/workflows/lint.yml": []byte(`name: Lint
on:
  workflow_call:
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: golangci/golangci-lint-action@v3
`),
			"actions/checkout/v4/action.yml": []byte(`name: Checkout
runs:
  using: node20
  main: index.js
`),
			"golangci/golangci-lint-action/v3/action.yml": []byte(`name: Lint
runs:
  using: node20
  main: index.js
`),
		},
	}

	r := &Resolver{
		fetcher: mock,
		opts:    Options{MaxDepth: 10, Quiet: true},
		seen:    make(map[string]bool),
		memo:    make(map[string][]*model.ActionRef),
	}

	ref := &model.ActionRef{
		Raw:        "org/repo/.github/workflows/lint.yml@main",
		Owner:      "org",
		Repo:       "repo",
		Ref:        "main",
		Path:       ".github/workflows/lint.yml",
		ActionType: model.ActionTypeReusable,
	}

	r.resolveAction(ref, 0)

	if ref.ResolveError != "" {
		t.Errorf("unexpected error: %s", ref.ResolveError)
	}
	if len(ref.Dependencies) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(ref.Dependencies))
	}
}
