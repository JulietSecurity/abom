package model

import (
	"fmt"
	"regexp"
	"strings"
)

// ActionType classifies the kind of uses: reference.
type ActionType string

const (
	ActionTypeStandard     ActionType = "standard"
	ActionTypeSubdirectory ActionType = "subdirectory"
	ActionTypeLocal        ActionType = "local"
	ActionTypeDocker       ActionType = "docker"
	ActionTypeReusable     ActionType = "reusable"
)

// RefType classifies how an action reference is pinned.
type RefType string

const (
	RefTypeSHA    RefType = "sha"
	RefTypeTag    RefType = "tag"
	RefTypeBranch RefType = "branch"
)

// ActionRef represents a single GitHub Action reference parsed from a uses: directive.
type ActionRef struct {
	Raw          string      `json:"uses"`
	Owner        string      `json:"owner,omitempty"`
	Repo         string      `json:"repo,omitempty"`
	Path         string      `json:"path,omitempty"`
	Ref          string      `json:"ref,omitempty"`
	RefType      RefType     `json:"ref_type,omitempty"`
	ActionType   ActionType  `json:"type"`
	Pinned       bool        `json:"pinned"`
	ResolvedSHA  string      `json:"resolved_sha,omitempty"`
	Dependencies []*ActionRef `json:"dependencies,omitempty"`
	Compromised  bool        `json:"compromised,omitempty"`
	Advisory     string      `json:"advisory,omitempty"`
	ResolveError  string      `json:"resolve_error,omitempty"`
	ReferencedBy  []string    `json:"referenced_by,omitempty"`
	DetectedTools []string    `json:"detected_tools,omitempty"`
}

var (
	shaPattern      = regexp.MustCompile(`^[0-9a-f]{40}$`)
	shortSHAPattern = regexp.MustCompile(`^[0-9a-f]{7,39}$`)
	tagPattern      = regexp.MustCompile(`^v?\d+(\.\d+)*`)
	// safeNamePattern validates owner/repo components to prevent URL injection.
	safeNamePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
)

// ParseActionRef parses a uses: string into a structured ActionRef.
func ParseActionRef(raw string) (*ActionRef, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty action reference")
	}

	ref := &ActionRef{Raw: raw}

	// Docker action: docker://image:tag
	if strings.HasPrefix(raw, "docker://") {
		ref.ActionType = ActionTypeDocker
		ref.Path = strings.TrimPrefix(raw, "docker://")
		return ref, nil
	}

	// Local action: ./path or ../path
	if strings.HasPrefix(raw, "./") || strings.HasPrefix(raw, "../") {
		ref.ActionType = ActionTypeLocal
		ref.Path = raw
		return ref, nil
	}

	// Split into path and ref at @
	parts := strings.SplitN(raw, "@", 2)
	if len(parts) != 2 || parts[1] == "" {
		return nil, fmt.Errorf("invalid action reference (missing @ref): %s", raw)
	}

	actionPath := parts[0]
	actionRef := parts[1]
	ref.Ref = actionRef

	classifyRef(ref, actionRef)

	// Reusable workflow: org/repo/.github/workflows/file.yml@ref
	if strings.Contains(actionPath, ".github/workflows/") &&
		(strings.HasSuffix(actionPath, ".yml") || strings.HasSuffix(actionPath, ".yaml")) {
		ref.ActionType = ActionTypeReusable
		pathParts := strings.SplitN(actionPath, "/", 3)
		if len(pathParts) >= 2 {
			ref.Owner = pathParts[0]
			ref.Repo = pathParts[1]
		}
		if !safeNamePattern.MatchString(ref.Owner) || !safeNamePattern.MatchString(ref.Repo) {
			return nil, fmt.Errorf("invalid characters in action reference: %s", raw)
		}
		if len(pathParts) >= 3 {
			ref.Path = pathParts[2]
		}
		return ref, nil
	}

	// Standard or subdirectory action
	pathParts := strings.SplitN(actionPath, "/", 3)
	if len(pathParts) < 2 {
		return nil, fmt.Errorf("invalid action reference (need owner/repo): %s", raw)
	}

	ref.Owner = pathParts[0]
	ref.Repo = pathParts[1]

	if !safeNamePattern.MatchString(ref.Owner) || !safeNamePattern.MatchString(ref.Repo) {
		return nil, fmt.Errorf("invalid characters in action reference: %s", raw)
	}

	if len(pathParts) == 2 {
		ref.ActionType = ActionTypeStandard
	} else {
		ref.ActionType = ActionTypeSubdirectory
		ref.Path = pathParts[2]
	}

	return ref, nil
}

func classifyRef(ref *ActionRef, r string) {
	switch {
	case shaPattern.MatchString(r):
		ref.RefType = RefTypeSHA
		ref.Pinned = true
	case shortSHAPattern.MatchString(r):
		ref.RefType = RefTypeSHA
		ref.Pinned = true
	case tagPattern.MatchString(r):
		ref.RefType = RefTypeTag
	default:
		ref.RefType = RefTypeBranch
	}
}
