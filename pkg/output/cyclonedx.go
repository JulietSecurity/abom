package output

import (
	"fmt"
	"io"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/julietsecurity/abom/pkg/model"
)

// CycloneDXFormatter outputs an ABOM as CycloneDX 1.5 JSON.
type CycloneDXFormatter struct{}

func NewCycloneDXFormatter() *CycloneDXFormatter {
	return &CycloneDXFormatter{}
}

func (f *CycloneDXFormatter) Format(abom *model.ABOM, w io.Writer) error {
	bom := cdx.NewBOM()

	bom.Metadata = &cdx.Metadata{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{
				{
					Type:    cdx.ComponentTypeApplication,
					Name:    "abom",
					Version: abom.Metadata.Version,
				},
			},
		},
		Component: &cdx.Component{
			Type:   cdx.ComponentTypeApplication,
			Name:   abom.Source.Target,
			BOMRef: abom.Source.Target,
		},
	}

	// Build components from flat action list
	var components []cdx.Component
	var vulnerabilities []cdx.Vulnerability
	var dependencies []cdx.Dependency

	// Root dependency
	var rootDeps []string

	for _, wf := range abom.Workflows {
		for _, job := range wf.Jobs {
			for _, step := range job.Steps {
				if step.Action != nil {
					bomRef := actionBOMRef(step.Action)
					rootDeps = appendUnique(rootDeps, bomRef)
				}
			}
		}
	}

	dependencies = append(dependencies, cdx.Dependency{
		Ref:          abom.Source.Target,
		Dependencies: strSlicePtr(rootDeps),
	})

	// Process all unique actions
	seen := make(map[string]bool)
	for _, ref := range abom.Actions {
		addCycloneDXComponents(ref, seen, &components, &vulnerabilities, &dependencies)
	}

	bom.Components = &components
	if len(vulnerabilities) > 0 {
		bom.Vulnerabilities = &vulnerabilities
	}
	bom.Dependencies = &dependencies

	enc := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	return enc.EncodeVersion(bom, cdx.SpecVersion1_5)
}

func addCycloneDXComponents(ref *model.ActionRef, seen map[string]bool, components *[]cdx.Component, vulnerabilities *[]cdx.Vulnerability, dependencies *[]cdx.Dependency) {
	bomRef := actionBOMRef(ref)
	if seen[bomRef] {
		return
	}
	seen[bomRef] = true

	comp := cdx.Component{
		Type:       cdx.ComponentTypeLibrary,
		BOMRef:     bomRef,
		Group:      ref.Owner,
		Name:       componentName(ref),
		Version:    ref.Ref,
		PackageURL: actionPURL(ref),
	}
	*components = append(*components, comp)

	// Dependency entry
	var depRefs []string
	for _, dep := range ref.Dependencies {
		depRefs = append(depRefs, actionBOMRef(dep))
		addCycloneDXComponents(dep, seen, components, vulnerabilities, dependencies)
	}
	*dependencies = append(*dependencies, cdx.Dependency{
		Ref:          bomRef,
		Dependencies: strSlicePtr(depRefs),
	})

	// Vulnerability entry
	if ref.Compromised && ref.Advisory != "" {
		vuln := cdx.Vulnerability{
			ID:          ref.Advisory,
			Description: fmt.Sprintf("Compromised action: %s", ref.Raw),
			Source: &cdx.Source{
				Name: "NVD",
				URL:  "https://nvd.nist.gov/",
			},
			Affects: &[]cdx.Affects{
				{Ref: bomRef},
			},
		}
		*vulnerabilities = append(*vulnerabilities, vuln)
	}
}

func actionBOMRef(ref *model.ActionRef) string {
	switch ref.ActionType {
	case model.ActionTypeDocker:
		return "docker://" + ref.Path
	case model.ActionTypeLocal:
		return ref.Path
	default:
		name := ref.Owner + "/" + ref.Repo
		if ref.Path != "" && ref.ActionType == model.ActionTypeSubdirectory {
			name += "/" + ref.Path
		}
		return name + "@" + ref.Ref
	}
}

func componentName(ref *model.ActionRef) string {
	switch ref.ActionType {
	case model.ActionTypeDocker:
		return ref.Path
	case model.ActionTypeLocal:
		return ref.Path
	default:
		name := ref.Owner + "/" + ref.Repo
		if ref.Path != "" && ref.ActionType == model.ActionTypeSubdirectory {
			name += "/" + ref.Path
		}
		return name
	}
}

func actionPURL(ref *model.ActionRef) string {
	if ref.Owner == "" || ref.Repo == "" {
		return ""
	}
	return fmt.Sprintf("pkg:githubactions/%s/%s@%s", ref.Owner, ref.Repo, ref.Ref)
}

func strSlicePtr(s []string) *[]string {
	if len(s) == 0 {
		return nil
	}
	return &s
}

func appendUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}
