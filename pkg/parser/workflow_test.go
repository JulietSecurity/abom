package parser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/julietsecurity/abom/pkg/model"
)

func TestParseWorkflow_Simple(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "workflows", "simple.yml"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	wf, err := ParseWorkflow(data, "simple.yml")
	if err != nil {
		t.Fatalf("parsing workflow: %v", err)
	}

	if wf.Name != "CI" {
		t.Errorf("Name = %q, want %q", wf.Name, "CI")
	}

	if len(wf.Jobs) != 1 {
		t.Fatalf("got %d jobs, want 1", len(wf.Jobs))
	}

	job := wf.Jobs[0]
	if job.ID != "build" {
		t.Errorf("Job.ID = %q, want %q", job.ID, "build")
	}

	if len(job.Steps) != 2 {
		t.Fatalf("got %d steps with uses, want 2", len(job.Steps))
	}

	// actions/checkout@v4
	step0 := job.Steps[0]
	if step0.Action.Owner != "actions" || step0.Action.Repo != "checkout" {
		t.Errorf("step 0: got %s/%s, want actions/checkout", step0.Action.Owner, step0.Action.Repo)
	}
	if step0.Action.Ref != "v4" {
		t.Errorf("step 0 ref = %q, want %q", step0.Action.Ref, "v4")
	}

	// actions/setup-go@v5
	step1 := job.Steps[1]
	if step1.Name != "Setup Go" {
		t.Errorf("step 1 name = %q, want %q", step1.Name, "Setup Go")
	}
	if step1.Action.Owner != "actions" || step1.Action.Repo != "setup-go" {
		t.Errorf("step 1: got %s/%s, want actions/setup-go", step1.Action.Owner, step1.Action.Repo)
	}
}

func TestParseWorkflow_Complex(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "workflows", "complex.yml"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	wf, err := ParseWorkflow(data, "complex.yml")
	if err != nil {
		t.Fatalf("parsing workflow: %v", err)
	}

	if wf.Name != "Complex" {
		t.Errorf("Name = %q, want %q", wf.Name, "Complex")
	}

	// Should have 2 jobs: lint (reusable workflow) and build (steps)
	if len(wf.Jobs) != 2 {
		t.Fatalf("got %d jobs, want 2", len(wf.Jobs))
	}

	// Find each job by ID since map iteration order is random
	jobByID := make(map[string]*model.Job)
	for _, j := range wf.Jobs {
		jobByID[j.ID] = j
	}

	// lint job — reusable workflow
	lint, ok := jobByID["lint"]
	if !ok {
		t.Fatal("missing lint job")
	}
	if lint.Uses != "org/repo/.github/workflows/lint.yml@main" {
		t.Errorf("lint.Uses = %q", lint.Uses)
	}
	if len(lint.Steps) != 1 {
		t.Fatalf("lint: got %d steps, want 1", len(lint.Steps))
	}
	if lint.Steps[0].Action.ActionType != model.ActionTypeReusable {
		t.Errorf("lint step type = %q, want reusable", lint.Steps[0].Action.ActionType)
	}

	// build job — 4 steps with uses
	build, ok := jobByID["build"]
	if !ok {
		t.Fatal("missing build job")
	}
	if len(build.Steps) != 4 {
		t.Fatalf("build: got %d steps, want 4", len(build.Steps))
	}

	// SHA-pinned checkout
	if build.Steps[0].Action.ActionType != model.ActionTypeStandard {
		t.Errorf("step 0 type = %q, want standard", build.Steps[0].Action.ActionType)
	}
	if !build.Steps[0].Action.Pinned {
		t.Error("step 0 should be pinned (SHA)")
	}

	// Local action
	if build.Steps[1].Action.ActionType != model.ActionTypeLocal {
		t.Errorf("step 1 type = %q, want local", build.Steps[1].Action.ActionType)
	}

	// Docker action
	if build.Steps[2].Action.ActionType != model.ActionTypeDocker {
		t.Errorf("step 2 type = %q, want docker", build.Steps[2].Action.ActionType)
	}

	// Subdirectory action
	if build.Steps[3].Action.ActionType != model.ActionTypeSubdirectory {
		t.Errorf("step 3 type = %q, want subdirectory", build.Steps[3].Action.ActionType)
	}
}

func TestParseActionFile_Composite(t *testing.T) {
	content := []byte(`name: My Composite
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
    - uses: aquasecurity/trivy-action@v1
    - name: Run script
      run: echo hello
`)

	refs, err := ParseActionFile(content)
	if err != nil {
		t.Fatalf("parsing action file: %v", err)
	}

	if len(refs) != 2 {
		t.Fatalf("got %d refs, want 2", len(refs))
	}

	if refs[0].Owner != "actions" || refs[0].Repo != "checkout" {
		t.Errorf("ref 0: got %s/%s, want actions/checkout", refs[0].Owner, refs[0].Repo)
	}
	if refs[1].Owner != "aquasecurity" || refs[1].Repo != "trivy-action" {
		t.Errorf("ref 1: got %s/%s, want aquasecurity/trivy-action", refs[1].Owner, refs[1].Repo)
	}
}

func TestParseActionFile_Node(t *testing.T) {
	content := []byte(`name: My Node Action
runs:
  using: node20
  main: index.js
`)

	refs, err := ParseActionFile(content)
	if err != nil {
		t.Fatalf("parsing action file: %v", err)
	}

	if refs != nil {
		t.Errorf("expected nil refs for node action, got %d", len(refs))
	}
}

func TestParseActionFileFull_DetectsTools(t *testing.T) {
	// Simulates crazy-max/ghaction-container-scan action.yml
	content := []byte(`name: Container Scan
description: Check for vulnerabilities in your container image
inputs:
  trivy_version:
    description: 'Trivy CLI version (eg. v0.20.0)'
    default: 'latest'
  image:
    description: 'Container image to scan'
runs:
  using: node20
  main: index.js
`)

	result, err := ParseActionFileFull(content)
	if err != nil {
		t.Fatalf("parsing action file: %v", err)
	}

	if len(result.DetectedTools) == 0 {
		t.Fatal("expected detected tools, got none")
	}

	found := false
	for _, tool := range result.DetectedTools {
		if tool == "trivy" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'trivy' in detected tools, got %v", result.DetectedTools)
	}
}

func TestParseActionFileFull_NoFalsePositives(t *testing.T) {
	content := []byte(`name: Checkout
description: Checkout a repository
inputs:
  ref:
    description: 'The branch, tag or SHA to checkout'
runs:
  using: node20
  main: index.js
`)

	result, err := ParseActionFileFull(content)
	if err != nil {
		t.Fatalf("parsing action file: %v", err)
	}

	if len(result.DetectedTools) != 0 {
		t.Errorf("expected no detected tools for checkout action, got %v", result.DetectedTools)
	}
}

func TestParseActionFileFull_DockerImage(t *testing.T) {
	content := []byte(`name: Trivy Scanner
description: Run trivy scanner
runs:
  using: docker
  image: 'docker://aquasec/trivy:latest'
`)

	result, err := ParseActionFileFull(content)
	if err != nil {
		t.Fatalf("parsing action file: %v", err)
	}

	found := false
	for _, tool := range result.DetectedTools {
		if tool == "trivy" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'trivy' in detected tools from docker image, got %v", result.DetectedTools)
	}
}
