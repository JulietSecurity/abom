package advisory

import (
	"testing"

	"github.com/julietsecurity/abom/pkg/model"
)

func testDB() *Database {
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
			name: "trivy-action max vulnerable",
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
			name: "trivy-action fixed boundary",
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
			name: "trivy-action above fixed",
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
			name: "setup-trivy fixed",
			ref: &model.ActionRef{
				Owner:      "aquasecurity",
				Repo:       "setup-trivy",
				Ref:        "v0.2.6",
				RefType:    model.RefTypeTag,
				ActionType: model.ActionTypeStandard,
			},
		},
		{
			name: "setup-trivy above fixed",
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
		{
			name: "tj-actions vulnerable",
			ref: &model.ActionRef{
				Owner:      "tj-actions",
				Repo:       "changed-files",
				Ref:        "v45",
				RefType:    model.RefTypeTag,
				ActionType: model.ActionTypeStandard,
			},
			wantHit:    true,
			wantResult: "compromised",
		},
		{
			name: "tj-actions fixed",
			ref: &model.ActionRef{
				Owner:      "tj-actions",
				Repo:       "changed-files",
				Ref:        "v46.0.1",
				RefType:    model.RefTypeTag,
				ActionType: model.ActionTypeStandard,
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

func TestMatchesRange(t *testing.T) {
	rng := &Range{
		Type: "ECOSYSTEM",
		Events: []Event{
			{Introduced: "v0.0.1"},
			{Fixed: "v0.35.0"},
		},
	}

	tests := []struct {
		version string
		want    bool
	}{
		{"v0.20.0", true},
		{"v0.0.1", true},
		{"v0.34.2", true},
		{"v0.35.0", false},
		{"v0.0.0", false},
		{"v1.0.0", false},
		{"main", false}, // non-numeric returns empty, falls before introduced
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := matchesRange(tt.version, rng)
			if got != tt.want {
				t.Errorf("matchesRange(%q, range) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestMatchesRange_IntroducedZero(t *testing.T) {
	// "0" is the OSV sentinel for "from the beginning."
	rng := &Range{
		Type: "ECOSYSTEM",
		Events: []Event{
			{Introduced: "0"},
			{Fixed: "v2.0.0"},
		},
	}

	tests := []struct {
		version string
		want    bool
	}{
		{"v0.0.1", true},
		{"v1.5.0", true},
		{"v2.0.0", false},
		{"v3.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			if got := matchesRange(tt.version, rng); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchesRange_LastAffected(t *testing.T) {
	rng := &Range{
		Type: "ECOSYSTEM",
		Events: []Event{
			{Introduced: "v1.0.0"},
			{LastAffected: "v1.5.0"},
		},
	}

	tests := []struct {
		version string
		want    bool
	}{
		{"v0.9.0", false},
		{"v1.0.0", true},
		{"v1.5.0", true},
		{"v1.5.1", false},
		{"v2.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			if got := matchesRange(tt.version, rng); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuiltinDataLoads(t *testing.T) {
	db := testDB()
	if len(db.db.Advisories) == 0 {
		t.Fatal("builtin data should contain at least one advisory")
	}
	ids := make(map[string]bool)
	for _, adv := range db.db.Advisories {
		ids[adv.ID] = true
	}
	if !ids["ABOM-2026-001"] {
		t.Error("builtin data missing ABOM-2026-001")
	}
	if !ids["ABOM-2026-002"] {
		t.Error("builtin data missing ABOM-2026-002")
	}
	if db.source != "builtin" {
		t.Errorf("source = %q, want builtin", db.source)
	}
}

func TestBuiltinDataIsOSV(t *testing.T) {
	db := testDB()
	for _, adv := range db.db.Advisories {
		if adv.SchemaVersion == "" {
			t.Errorf("%s missing schema_version", adv.ID)
		}
		if len(adv.Affected) == 0 {
			t.Errorf("%s has no affected packages", adv.ID)
		}
		for _, aff := range adv.Affected {
			if aff.Package.Ecosystem == "" {
				t.Errorf("%s has affected entry with no ecosystem", adv.ID)
			}
		}
	}
}
