package resolver

import "testing"

func TestParseRemoteTarget(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantNil   bool
		wantOwner string
		wantRepo  string
		wantRef   string
	}{
		{
			name:      "basic github.com",
			input:     "github.com/org/repo",
			wantOwner: "org",
			wantRepo:  "repo",
		},
		{
			name:      "with ref",
			input:     "github.com/org/repo@main",
			wantOwner: "org",
			wantRepo:  "repo",
			wantRef:   "main",
		},
		{
			name:      "with https prefix",
			input:     "https://github.com/org/repo",
			wantOwner: "org",
			wantRepo:  "repo",
		},
		{
			name:      "with tag ref",
			input:     "github.com/org/repo@v1.2.3",
			wantOwner: "org",
			wantRepo:  "repo",
			wantRef:   "v1.2.3",
		},
		{
			name:      "trailing slash",
			input:     "github.com/org/repo/",
			wantOwner: "org",
			wantRepo:  "repo",
		},
		{
			name:    "local path",
			input:   "/path/to/repo",
			wantNil: true,
		},
		{
			name:    "relative path",
			input:   ".",
			wantNil: true,
		},
		{
			name:    "incomplete github path",
			input:   "github.com/org",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseRemoteTarget(tt.input)
			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %+v", result)
				}
				return
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			if result.Owner != tt.wantOwner {
				t.Errorf("Owner = %q, want %q", result.Owner, tt.wantOwner)
			}
			if result.Repo != tt.wantRepo {
				t.Errorf("Repo = %q, want %q", result.Repo, tt.wantRepo)
			}
			if result.Ref != tt.wantRef {
				t.Errorf("Ref = %q, want %q", result.Ref, tt.wantRef)
			}
		})
	}
}
