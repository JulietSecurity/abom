package advisory

import (
	"testing"

	"github.com/julietsecurity/abom/pkg/model"
)

func testDB() *Database {
	// Load from builtin data directly, skip network
	return NewDatabase(LoadOptions{Offline: true, Quiet: true})
}

func TestCheck_TrivyActionVulnerable(t *testing.T) {
	db := testDB()

	tests := []struct {
		name       string
		ref        *model.ActionRef
		wantHit    bool
		wantResult string
	}{
		{
			name: "trivy-action vulnerable tag",
			ref: &model.ActionRef{
				Owner:      "aquasecurity",
				Repo:       "trivy-action",
				Ref:        "v0.20.0",
				RefType:    model.RefTypeTag,
				ActionType: model.ActionTypeStandard,
			},
			wantHit:    true,
			wantResult: "compromised",
		},
		{
			name: "trivy-action min boundary",
			ref: &model.ActionRef{
				Owner:      "aquasecurity",
				Repo:       "trivy-action",
				Ref:        "v0.0.1",
				RefType:    model.RefTypeTag,
				ActionType: model.ActionTypeStandard,
			},
			wantHit:    true,
			wantResult: "compromised",
		},
		{
			name: "trivy-action max boundary",
			ref: &model.ActionRef{
				Owner:      "aquasecurity",
				Repo:       "trivy-action",
				Ref:        "v0.34.2",
				RefType:    model.RefTypeTag,
				ActionType: model.ActionTypeStandard,
			},
			wantHit:    true,
			wantResult: "compromised",
		},
		{
			name: "trivy-action safe tag (above range and in safe_tags)",
			ref: &model.ActionRef{
				Owner:      "aquasecurity",
				Repo:       "trivy-action",
				Ref:        "v0.35.0",
				RefType:    model.RefTypeTag,
				ActionType: model.ActionTypeStandard,
			},
			wantHit: false,
		},
		{
			name: "trivy-action above range but not in safe_tags",
			ref: &model.ActionRef{
				Owner:      "aquasecurity",
				Repo:       "trivy-action",
				Ref:        "v1.0.0",
				RefType:    model.RefTypeTag,
				ActionType: model.ActionTypeStandard,
			},
			wantHit: false,
		},
		{
			name: "setup-trivy vulnerable",
			ref: &model.ActionRef{
				Owner:      "aquasecurity",
				Repo:       "setup-trivy",
				Ref:        "v0.2.3",
				RefType:    model.RefTypeTag,
				ActionType: model.ActionTypeStandard,
			},
			wantHit:    true,
			wantResult: "compromised",
		},
		{
			name: "setup-trivy safe tag",
			ref: &model.ActionRef{
				Owner:      "aquasecurity",
				Repo:       "setup-trivy",
				Ref:        "v0.2.6",
				RefType:    model.RefTypeTag,
				ActionType: model.ActionTypeStandard,
			},
		},
		{
			name: "setup-trivy above range",
			ref: &model.ActionRef{
				Owner:      "aquasecurity",
				Repo:       "setup-trivy",
				Ref:        "v0.3.0",
				RefType:    model.RefTypeTag,
				ActionType: model.ActionTypeStandard,
			},
		},
		{
			name: "trivy docker image indicator",
			ref: &model.ActionRef{
				ActionType: model.ActionTypeDocker,
				Path:       "aquasec/trivy:0.69.4",
			},
			wantHit:    true,
			wantResult: "compromised",
		},
		{
			name: "unrelated action",
			ref: &model.ActionRef{
				Owner:      "actions",
				Repo:       "checkout",
				Ref:        "v4",
				RefType:    model.RefTypeTag,
				ActionType: model.ActionTypeStandard,
			},
		},
		{
			name: "trivy-action with branch ref",
			ref: &model.ActionRef{
				Owner:      "aquasecurity",
				Repo:       "trivy-action",
				Ref:        "main",
				RefType:    model.RefTypeBranch,
				ActionType: model.ActionTypeStandard,
			},
		},
		{
			name: "trivy-action pinned to SHA — verify manually",
			ref: &model.ActionRef{
				Owner:      "aquasecurity",
				Repo:       "trivy-action",
				Ref:        "abcdef1234567890abcdef1234567890abcdef12",
				RefType:    model.RefTypeSHA,
				ActionType: model.ActionTypeStandard,
				Pinned:     true,
			},
			wantHit:    true,
			wantResult: "verify-sha",
		},
		{
			name: "local action not matched",
			ref: &model.ActionRef{
				ActionType: model.ActionTypeLocal,
				Path:       "./local-action",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adv, result := db.Check(tt.ref)
			if tt.wantHit && adv == nil {
				t.Error("expected advisory hit, got nil")
			}
			if !tt.wantHit && adv != nil {
				t.Errorf("expected no hit, got %s (result=%s)", adv.ID, result)
			}
			if tt.wantResult != "" && result != tt.wantResult {
				t.Errorf("result = %q, want %q", result, tt.wantResult)
			}
		})
	}
}

func TestCheckAll(t *testing.T) {
	db := testDB()

	abom := &model.ABOM{
		Workflows: []*model.Workflow{
			{
				Path: ".github/workflows/ci.yml",
				Jobs: []*model.Job{
					{
						ID: "security",
						Steps: []*model.Step{
							{
								Name: "scan",
								Action: &model.ActionRef{
									Raw:        "aquasecurity/trivy-action@v0.20.0",
									Owner:      "aquasecurity",
									Repo:       "trivy-action",
									Ref:        "v0.20.0",
									RefType:    model.RefTypeTag,
									ActionType: model.ActionTypeStandard,
								},
							},
							{
								Name: "checkout",
								Action: &model.ActionRef{
									Raw:        "actions/checkout@v4",
									Owner:      "actions",
									Repo:       "checkout",
									Ref:        "v4",
									RefType:    model.RefTypeTag,
									ActionType: model.ActionTypeStandard,
								},
							},
						},
					},
				},
			},
		},
	}

	db.CheckAll(abom)

	trivyStep := abom.Workflows[0].Jobs[0].Steps[0]
	if !trivyStep.Action.Compromised {
		t.Error("trivy-action should be marked compromised")
	}
	if trivyStep.Action.Advisory != "ABOM-2026-001" {
		t.Errorf("advisory = %q, want ABOM-2026-001", trivyStep.Action.Advisory)
	}

	checkoutStep := abom.Workflows[0].Jobs[0].Steps[1]
	if checkoutStep.Action.Compromised {
		t.Error("checkout should not be marked compromised")
	}
}

func TestMatchesTagRange(t *testing.T) {
	tests := []struct {
		version string
		rangeS  string
		want    bool
	}{
		{"v0.20.0", ">=v0.0.1 <=v0.34.2", true},
		{"v0.0.1", ">=v0.0.1 <=v0.34.2", true},
		{"v0.34.2", ">=v0.0.1 <=v0.34.2", true},
		{"v0.35.0", ">=v0.0.1 <=v0.34.2", false},
		{"v0.0.0", ">=v0.0.1 <=v0.34.2", false},
		{"main", ">=v0.0.1 <=v0.34.2", false},
		{"v1.0.0", ">=v0.0.1 <=v0.34.2", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := matchesTagRange(tt.version, tt.rangeS)
			if got != tt.want {
				t.Errorf("matchesTagRange(%q, %q) = %v, want %v", tt.version, tt.rangeS, got, tt.want)
			}
		})
	}
}

func TestBuiltinDataLoads(t *testing.T) {
	db := testDB()
	if len(db.db.Advisories) == 0 {
		t.Fatal("builtin data should contain at least one advisory")
	}
	if db.db.Advisories[0].ID != "ABOM-2026-001" {
		t.Errorf("first advisory ID = %q, want ABOM-2026-001", db.db.Advisories[0].ID)
	}
	if db.source != "builtin" {
		t.Errorf("source = %q, want builtin", db.source)
	}
}
