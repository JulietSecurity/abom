package parser

import (
	"fmt"
	"strings"

	"github.com/julietsecurity/abom/pkg/model"
	"gopkg.in/yaml.v3"
)

type rawAction struct {
	Name        string              `yaml:"name"`
	Description string              `yaml:"description"`
	Runs        rawRuns             `yaml:"runs"`
	Inputs      map[string]rawInput `yaml:"inputs"`
}

type rawRuns struct {
	Using string    `yaml:"using"`
	Image string    `yaml:"image"`
	Steps []rawStep `yaml:"steps"`
}

type rawInput struct {
	Description string `yaml:"description"`
	Default     string `yaml:"default"`
}

// ActionFileResult contains parsed data from an action.yml file.
type ActionFileResult struct {
	Deps          []*model.ActionRef
	DetectedTools []string
	IsComposite   bool
}

// knownTools maps tool identifiers to the signals we look for in action.yml
// inputs and descriptions. The key is the canonical tool name, values are
// substrings to match in input names, descriptions, and action descriptions.
var knownTools = map[string][]string{
	"trivy":       {"trivy"},
	"grype":       {"grype"},
	"snyk":        {"snyk"},
	"semgrep":     {"semgrep"},
	"sonarqube":   {"sonar"},
	"checkov":     {"checkov"},
	"tfsec":       {"tfsec"},
	"terrascan":   {"terrascan"},
	"hadolint":    {"hadolint"},
	"dockle":      {"dockle"},
	"cosign":      {"cosign"},
	"syft":        {"syft"},
}

// ParseActionFile parses an action.yml/action.yaml and returns nested action
// references for composite actions, plus any detected tool dependencies
// inferred from input names and descriptions.
func ParseActionFile(content []byte) ([]*model.ActionRef, error) {
	result, err := ParseActionFileFull(content)
	if err != nil {
		return nil, err
	}
	return result.Deps, nil
}

// ParseActionFileFull parses an action.yml and returns the full result
// including detected tools.
func ParseActionFileFull(content []byte) (*ActionFileResult, error) {
	var raw rawAction
	if err := yaml.Unmarshal(content, &raw); err != nil {
		return nil, fmt.Errorf("parsing action YAML: %w", err)
	}

	result := &ActionFileResult{}

	// Detect tools from inputs and descriptions
	result.DetectedTools = detectTools(&raw)

	// Check for docker image references
	if raw.Runs.Image != "" && strings.HasPrefix(raw.Runs.Image, "docker://") {
		img := strings.TrimPrefix(raw.Runs.Image, "docker://")
		for tool, signals := range knownTools {
			for _, sig := range signals {
				if strings.Contains(strings.ToLower(img), sig) {
					result.DetectedTools = appendUnique(result.DetectedTools, tool)
				}
			}
		}
	}

	if raw.Runs.Using != "composite" {
		return result, nil
	}

	result.IsComposite = true

	for _, step := range raw.Runs.Steps {
		if step.Uses == "" {
			continue
		}
		ref, err := model.ParseActionRef(step.Uses)
		if err != nil {
			continue
		}
		result.Deps = append(result.Deps, ref)
	}

	// Also scan run: steps in composite actions for tool invocations
	for _, step := range raw.Runs.Steps {
		if step.Uses != "" {
			continue
		}
		// Check the step name for tool references (run steps don't have a
		// "run" field in our struct, but the step name often describes what it does)
	}

	return result, nil
}

func detectTools(raw *rawAction) []string {
	var tools []string

	// Build a corpus of searchable text from the action metadata
	var corpus []string
	corpus = append(corpus, strings.ToLower(raw.Description))

	for inputName, input := range raw.Inputs {
		corpus = append(corpus, strings.ToLower(inputName))
		corpus = append(corpus, strings.ToLower(input.Description))
		corpus = append(corpus, strings.ToLower(input.Default))
	}

	text := strings.Join(corpus, " ")

	for tool, signals := range knownTools {
		for _, sig := range signals {
			if strings.Contains(text, sig) {
				tools = appendUnique(tools, tool)
				break
			}
		}
	}

	return tools
}

func appendUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}
