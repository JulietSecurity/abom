package parser

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/julietsecurity/abom/pkg/model"
	"gopkg.in/yaml.v3"
)

type rawWorkflow struct {
	Name string            `yaml:"name"`
	Jobs map[string]rawJob `yaml:"jobs"`
}

type rawJob struct {
	Uses  string    `yaml:"uses"`
	Steps []rawStep `yaml:"steps"`
}

type rawStep struct {
	Name string `yaml:"name"`
	ID   string `yaml:"id"`
	Uses string `yaml:"uses"`
}

// ParseWorkflowFile reads and parses a workflow YAML file from disk.
func ParseWorkflowFile(path string) (*model.Workflow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading workflow file: %w", err)
	}
	return ParseWorkflow(data, path)
}

// ParseWorkflow parses workflow YAML bytes into a Workflow model.
func ParseWorkflow(data []byte, path string) (*model.Workflow, error) {
	var raw rawWorkflow
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing workflow YAML: %w", err)
	}

	wf := &model.Workflow{
		Path: path,
		Name: raw.Name,
	}

	for jobID, rawJob := range raw.Jobs {
		job := &model.Job{ID: jobID}

		// Job-level uses (reusable workflow call)
		if rawJob.Uses != "" {
			job.Uses = rawJob.Uses
			ref, err := model.ParseActionRef(rawJob.Uses)
			if err == nil {
				step := &model.Step{
					Name:   jobID,
					Uses:   rawJob.Uses,
					Action: ref,
				}
				job.Steps = append(job.Steps, step)
			}
		}

		// Step-level uses
		for _, rs := range rawJob.Steps {
			if rs.Uses == "" {
				continue
			}
			ref, err := model.ParseActionRef(rs.Uses)
			if err != nil {
				continue
			}
			step := &model.Step{
				Name:   rs.Name,
				ID:     rs.ID,
				Uses:   rs.Uses,
				Action: ref,
			}
			job.Steps = append(job.Steps, step)
		}

		if len(job.Steps) > 0 {
			wf.Jobs = append(wf.Jobs, job)
		}
	}

	return wf, nil
}

// ParseWorkflowDir finds and parses all workflow files in a repository root.
func ParseWorkflowDir(dir string) ([]*model.Workflow, error) {
	workflowDir := filepath.Join(dir, ".github", "workflows")

	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		return nil, fmt.Errorf("reading workflows directory: %w", err)
	}

	var workflows []*model.Workflow
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		ext := filepath.Ext(name)
		if ext != ".yml" && ext != ".yaml" {
			continue
		}

		fullPath := filepath.Join(workflowDir, name)
		wf, err := ParseWorkflowFile(fullPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: skipping %s: %v\n", name, err)
			continue
		}
		wf.Path = ".github/workflows/" + name
		workflows = append(workflows, wf)
	}

	return workflows, nil
}
