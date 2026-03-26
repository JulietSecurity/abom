package cmd

import (
	"fmt"
	"os"

	"github.com/julietsecurity/abom/pkg/advisory"
	"github.com/julietsecurity/abom/pkg/model"
	"github.com/julietsecurity/abom/pkg/output"
	"github.com/julietsecurity/abom/pkg/parser"
	"github.com/julietsecurity/abom/pkg/resolver"
	"github.com/spf13/cobra"
)

var (
	outputFormat  string
	outputFile    string
	checkAdvisory bool
	maxDepth      int
	noNetwork     bool
)

var scanCmd = &cobra.Command{
	Use:   "scan [path or github.com/owner/repo]",
	Short: "Scan a repository and generate an ABOM",
	Long: `Scan a local or remote repository, resolve all GitHub Action dependencies
(including transitive and embedded), and output an Actions Bill of Materials.

Output formats: table (default), json, cyclonedx-json, spdx-json`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table, json, cyclonedx-json, spdx-json")
	scanCmd.Flags().StringVarP(&outputFile, "file", "f", "", "Write output to file")
	scanCmd.Flags().BoolVar(&checkAdvisory, "check", false, "Flag known-compromised actions")
	scanCmd.Flags().IntVarP(&maxDepth, "depth", "d", 10, "Max recursion depth for transitive dependencies")
	scanCmd.Flags().BoolVar(&noNetwork, "no-network", false, "Skip resolving transitive dependencies")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	target := args[0]

	if !quiet {
		fmt.Fprintf(os.Stderr, "Scanning %s...\n", target)
	}

	var workflows []*model.Workflow
	var localRoot string

	// Check if target is a remote GitHub repo
	remote := resolver.ParseRemoteTarget(target)
	if remote != nil {
		if noNetwork {
			return fmt.Errorf("cannot scan remote repository with --no-network")
		}
		var sha string
		var err error
		workflows, sha, err = resolver.FetchRemoteWorkflows(remote, githubToken, quiet)
		if err != nil {
			return fmt.Errorf("fetching remote workflows: %w", err)
		}
		if !quiet {
			ref := remote.Ref
			if ref == "" {
				ref = "(default branch)"
			}
			fmt.Fprintf(os.Stderr, "Remote: %s/%s@%s\n", remote.Owner, remote.Repo, ref)
		}
		_ = sha // available for source metadata
	} else {
		// Local path
		info, err := os.Stat(target)
		if err != nil || !info.IsDir() {
			return fmt.Errorf("target must be a local directory or github.com/owner/repo: %s", target)
		}
		localRoot = target

		workflows, err = parser.ParseWorkflowDir(target)
		if err != nil {
			return fmt.Errorf("parsing workflows: %w", err)
		}
	}

	if len(workflows) == 0 {
		return fmt.Errorf("no workflow files found")
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "Found %d workflow(s)\n", len(workflows))
	}

	abom := model.NewABOM(target)
	abom.Workflows = workflows

	// Resolve transitive dependencies
	if !noNetwork {
		res, err := resolver.New(resolver.Options{
			MaxDepth:  maxDepth,
			Token:     githubToken,
			NoNetwork: noNetwork,
			Quiet:     quiet,
			LocalRoot: localRoot,
		})
		if err != nil {
			return fmt.Errorf("initializing resolver: %w", err)
		}
		if !quiet {
			fmt.Fprintf(os.Stderr, "Resolving transitive dependencies...\n")
		}
		if err := res.ResolveWorkflows(workflows); err != nil {
			return fmt.Errorf("resolving dependencies: %w", err)
		}
	}

	// Check advisories
	if checkAdvisory {
		db := advisory.NewDatabase(advisory.LoadOptions{
			Offline: offline,
			NoCache: noCache,
			Quiet:   quiet,
			Token:   githubToken,
		})
		db.CheckAll(abom)
	}

	abom.CollectActions()

	// Write output
	w := os.Stdout
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	var formatErr error
	switch outputFormat {
	case "table":
		formatter := output.NewTableFormatter()
		formatErr = formatter.Format(abom, w)
	case "json":
		formatter := output.NewJSONFormatter()
		formatErr = formatter.Format(abom, w)
	case "cyclonedx-json":
		formatter := output.NewCycloneDXFormatter()
		formatErr = formatter.Format(abom, w)
	case "spdx-json":
		formatter := output.NewSPDXFormatter()
		formatErr = formatter.Format(abom, w)
	default:
		return fmt.Errorf("unknown output format: %s", outputFormat)
	}

	if formatErr != nil {
		return formatErr
	}

	// Exit code 1 if compromised actions found (usable as CI gate)
	if checkAdvisory && abom.Summary.Compromised > 0 {
		os.Exit(1)
	}

	return nil
}
