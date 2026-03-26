package output

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/julietsecurity/abom/pkg/model"
)

// TableFormatter outputs an ABOM as a human-readable table.
type TableFormatter struct{}

func NewTableFormatter() *TableFormatter {
	return &TableFormatter{}
}

func (f *TableFormatter) Format(abom *model.ABOM, w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	fmt.Fprintf(tw, "WORKFLOW\tSTEP\tACTION\tREF\tSTATUS\n")

	for _, wf := range abom.Workflows {
		for _, job := range wf.Jobs {
			for _, step := range job.Steps {
				if step.Action == nil {
					continue
				}
				ref := step.Action
				stepName := step.Name
				if stepName == "" {
					stepName = step.ID
				}

				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
					wf.Path, stepName, formatActionName(ref), ref.Ref, formatStatus(ref))

				printDependencies(tw, ref.Dependencies, 1)
			}
		}
	}

	tw.Flush()

	// Summary
	fmt.Fprintln(w)
	if abom.Summary.TotalTransitive > 0 {
		fmt.Fprintf(w, "Transitive dependencies: %d actions resolved\n", abom.Summary.TotalTransitive)
	}
	if abom.Summary.Compromised > 0 {
		transitive := countTransitiveCompromised(abom)
		direct := abom.Summary.Compromised - transitive
		fmt.Fprintf(w, "Compromised actions found: %d (%d direct, %d transitive)\n",
			abom.Summary.Compromised, direct, transitive)
	}

	return nil
}

func printDependencies(tw *tabwriter.Writer, deps []*model.ActionRef, depth int) {
	for _, dep := range deps {
		indent := strings.Repeat("    ", depth-1) + "\u2514\u2500\u2500 "

		fmt.Fprintf(tw, "\t\t%s%s\t%s\t%s\n",
			indent, formatActionName(dep), dep.Ref, formatStatusTransitive(dep))

		printDependencies(tw, dep.Dependencies, depth+1)
	}
}

func formatActionName(ref *model.ActionRef) string {
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
		return name
	}
}

func formatStatus(ref *model.ActionRef) string {
	if ref.Compromised {
		return "COMPROMISED (" + ref.Advisory + ")"
	}

	switch ref.RefType {
	case model.RefTypeSHA:
		return "sha"
	case model.RefTypeTag:
		return "tag"
	case model.RefTypeBranch:
		return "branch"
	}
	return ""
}

func formatStatusTransitive(ref *model.ActionRef) string {
	if ref.Compromised {
		return "COMPROMISED (" + ref.Advisory + ", transitive)"
	}
	return formatStatus(ref)
}

func countTransitiveCompromised(abom *model.ABOM) int {
	count := 0
	for _, wf := range abom.Workflows {
		for _, job := range wf.Jobs {
			for _, step := range job.Steps {
				if step.Action != nil {
					count += countCompromisedInDeps(step.Action.Dependencies)
				}
			}
		}
	}
	return count
}

func countCompromisedInDeps(deps []*model.ActionRef) int {
	count := 0
	for _, dep := range deps {
		if dep.Compromised {
			count++
		}
		count += countCompromisedInDeps(dep.Dependencies)
	}
	return count
}
