package model

import (
	"testing"
)

func TestParseActionRef(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantType   ActionType
		wantOwner  string
		wantRepo   string
		wantPath   string
		wantRef    string
		wantRefTyp RefType
		wantPinned bool
		wantErr    bool
	}{
		{
			name:       "standard action with tag",
			raw:        "actions/checkout@v4",
			wantType:   ActionTypeStandard,
			wantOwner:  "actions",
			wantRepo:   "checkout",
			wantRef:    "v4",
			wantRefTyp: RefTypeTag,
		},
		{
			name:       "standard action with semver tag",
			raw:        "actions/setup-go@v5.2.1",
			wantType:   ActionTypeStandard,
			wantOwner:  "actions",
			wantRepo:   "setup-go",
			wantRef:    "v5.2.1",
			wantRefTyp: RefTypeTag,
		},
		{
			name:       "standard action with SHA",
			raw:        "actions/checkout@abcdef1234567890abcdef1234567890abcdef12",
			wantType:   ActionTypeStandard,
			wantOwner:  "actions",
			wantRepo:   "checkout",
			wantRef:    "abcdef1234567890abcdef1234567890abcdef12",
			wantRefTyp: RefTypeSHA,
			wantPinned: true,
		},
		{
			name:       "standard action with short SHA",
			raw:        "actions/checkout@abcdef1",
			wantType:   ActionTypeStandard,
			wantOwner:  "actions",
			wantRepo:   "checkout",
			wantRef:    "abcdef1",
			wantRefTyp: RefTypeSHA,
			wantPinned: true,
		},
		{
			name:       "standard action with branch",
			raw:        "actions/checkout@main",
			wantType:   ActionTypeStandard,
			wantOwner:  "actions",
			wantRepo:   "checkout",
			wantRef:    "main",
			wantRefTyp: RefTypeBranch,
		},
		{
			name:       "subdirectory action",
			raw:        "owner/repo/subdir@v1",
			wantType:   ActionTypeSubdirectory,
			wantOwner:  "owner",
			wantRepo:   "repo",
			wantPath:   "subdir",
			wantRef:    "v1",
			wantRefTyp: RefTypeTag,
		},
		{
			name:       "subdirectory action with deep path",
			raw:        "owner/repo/path/to/action@v2",
			wantType:   ActionTypeSubdirectory,
			wantOwner:  "owner",
			wantRepo:   "repo",
			wantPath:   "path/to/action",
			wantRef:    "v2",
			wantRefTyp: RefTypeTag,
		},
		{
			name:     "local action",
			raw:      "./.github/actions/my-action",
			wantType: ActionTypeLocal,
			wantPath: "./.github/actions/my-action",
		},
		{
			name:     "local action with parent dir",
			raw:      "../shared-action",
			wantType: ActionTypeLocal,
			wantPath: "../shared-action",
		},
		{
			name:     "docker action",
			raw:      "docker://alpine:3.18",
			wantType: ActionTypeDocker,
			wantPath: "alpine:3.18",
		},
		{
			name:     "docker action without tag",
			raw:      "docker://ubuntu",
			wantType: ActionTypeDocker,
			wantPath: "ubuntu",
		},
		{
			name:       "reusable workflow",
			raw:        "org/repo/.github/workflows/lint.yml@main",
			wantType:   ActionTypeReusable,
			wantOwner:  "org",
			wantRepo:   "repo",
			wantPath:   ".github/workflows/lint.yml",
			wantRef:    "main",
			wantRefTyp: RefTypeBranch,
		},
		{
			name:       "reusable workflow with yaml extension",
			raw:        "org/repo/.github/workflows/ci.yaml@v1",
			wantType:   ActionTypeReusable,
			wantOwner:  "org",
			wantRepo:   "repo",
			wantPath:   ".github/workflows/ci.yaml",
			wantRef:    "v1",
			wantRefTyp: RefTypeTag,
		},
		{
			name:    "empty string",
			raw:     "",
			wantErr: true,
		},
		{
			name:    "missing ref",
			raw:     "actions/checkout",
			wantErr: true,
		},
		{
			name:    "single component",
			raw:     "checkout@v4",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := ParseActionRef(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if ref.ActionType != tt.wantType {
				t.Errorf("ActionType = %q, want %q", ref.ActionType, tt.wantType)
			}
			if ref.Owner != tt.wantOwner {
				t.Errorf("Owner = %q, want %q", ref.Owner, tt.wantOwner)
			}
			if ref.Repo != tt.wantRepo {
				t.Errorf("Repo = %q, want %q", ref.Repo, tt.wantRepo)
			}
			if ref.Path != tt.wantPath {
				t.Errorf("Path = %q, want %q", ref.Path, tt.wantPath)
			}
			if ref.Ref != tt.wantRef {
				t.Errorf("Ref = %q, want %q", ref.Ref, tt.wantRef)
			}
			if ref.RefType != tt.wantRefTyp {
				t.Errorf("RefType = %q, want %q", ref.RefType, tt.wantRefTyp)
			}
			if ref.Pinned != tt.wantPinned {
				t.Errorf("Pinned = %v, want %v", ref.Pinned, tt.wantPinned)
			}
			if ref.Raw != tt.raw {
				t.Errorf("Raw = %q, want %q", ref.Raw, tt.raw)
			}
		})
	}
}
