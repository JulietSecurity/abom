package model

import "time"

// ABOM is the top-level Actions Bill of Materials.
type ABOM struct {
	Metadata  ABOMMetadata `json:"abom"`
	Source    Source       `json:"source"`
	Workflows []*Workflow  `json:"workflows"`
	Actions   []*ActionRef `json:"actions"`
	Summary   Summary      `json:"summary"`
}

// ABOMMetadata contains tool and generation info.
type ABOMMetadata struct {
	Version   string `json:"version"`
	Tool      string `json:"tool"`
	Generated string `json:"generated"`
}

// Source describes where the ABOM was generated from.
type Source struct {
	Type   string `json:"type"`
	Target string `json:"target"`
	Ref    string `json:"ref,omitempty"`
	SHA    string `json:"sha,omitempty"`
}

// Summary provides aggregate counts for the ABOM.
type Summary struct {
	TotalWorkflows  int `json:"total_workflows"`
	TotalActions    int `json:"total_actions"`
	TotalTransitive int `json:"total_transitive"`
	PinnedToSHA     int `json:"pinned_to_sha"`
	PinnedToTag     int `json:"pinned_to_tag"`
	Compromised     int `json:"compromised"`
}

// NewABOM creates a new ABOM with metadata initialized.
func NewABOM(target string) *ABOM {
	return &ABOM{
		Metadata: ABOMMetadata{
			Version:   "1.0.0",
			Tool:      "abom",
			Generated: time.Now().UTC().Format(time.RFC3339),
		},
		Source: Source{
			Type:   "git",
			Target: target,
		},
	}
}

// CollectActions walks the workflow tree and builds the deduplicated flat
// Actions list and computes Summary statistics.
func (a *ABOM) CollectActions() {
	seen := make(map[string]*ActionRef)
	var directCount, transitiveCount int

	for _, wf := range a.Workflows {
		for _, job := range wf.Jobs {
			for _, step := range job.Steps {
				if step.Action == nil {
					continue
				}
				provenance := wf.Path + " > " + job.ID
				if step.Name != "" {
					provenance += " > " + step.Name
				} else if step.ID != "" {
					provenance += " > " + step.ID
				}
				collectAction(seen, step.Action, provenance, true, &directCount, &transitiveCount)
			}
		}
	}

	a.Actions = make([]*ActionRef, 0, len(seen))
	for _, ref := range seen {
		a.Actions = append(a.Actions, ref)
	}

	a.Summary = Summary{
		TotalWorkflows:  len(a.Workflows),
		TotalActions:    directCount + transitiveCount,
		TotalTransitive: transitiveCount,
	}

	for _, ref := range a.Actions {
		switch ref.RefType {
		case RefTypeSHA:
			a.Summary.PinnedToSHA++
		case RefTypeTag:
			a.Summary.PinnedToTag++
		}
		if ref.Compromised {
			a.Summary.Compromised++
		}
	}
}

func collectAction(seen map[string]*ActionRef, ref *ActionRef, provenance string, direct bool, directCount, transitiveCount *int) {
	key := ref.Raw
	if existing, ok := seen[key]; ok {
		// Avoid duplicate provenance entries
		for _, p := range existing.ReferencedBy {
			if p == provenance {
				return
			}
		}
		existing.ReferencedBy = append(existing.ReferencedBy, provenance)
		return
	}
	ref.ReferencedBy = []string{provenance}
	seen[key] = ref
	if direct {
		*directCount++
	} else {
		*transitiveCount++
	}

	for _, dep := range ref.Dependencies {
		collectAction(seen, dep, provenance+" > "+ref.Raw, false, directCount, transitiveCount)
	}
}
