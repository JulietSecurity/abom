package model

// Workflow represents a parsed GitHub Actions workflow file.
type Workflow struct {
	Path string `json:"path"`
	Name string `json:"name"`
	Jobs []*Job `json:"jobs"`
}

// Job represents a single job within a workflow.
type Job struct {
	ID    string  `json:"id"`
	Uses  string  `json:"uses,omitempty"`
	Steps []*Step `json:"steps,omitempty"`
}

// Step represents a single step within a job.
type Step struct {
	Name   string     `json:"name,omitempty"`
	ID     string     `json:"id,omitempty"`
	Uses   string     `json:"uses,omitempty"`
	Action *ActionRef `json:"action,omitempty"`
}
