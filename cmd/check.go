package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/julietsecurity/abom/pkg/advisory"
	"github.com/julietsecurity/abom/pkg/model"
	"github.com/julietsecurity/abom/pkg/resolver"
	"github.com/julietsecurity/abom/pkg/warnings"
	"github.com/spf13/cobra"
)

var useStdin bool

var checkCmd = &cobra.Command{
	Use:   "check [file]",
	Short: "Check an existing ABOM against known-compromised actions",
	RunE:  runCheck,
}

func init() {
	checkCmd.Flags().BoolVar(&useStdin, "stdin", false, "Read ABOM from stdin")
	rootCmd.AddCommand(checkCmd)
}

func runCheck(cmd *cobra.Command, args []string) error {
	if verifyShas && offline {
		return fmt.Errorf("--verify-shas requires network; remove --offline")
	}

	col := &warnings.Collector{}

	if verifyShas && githubToken == "" {
		col.Emit(warnings.Warning{
			Category: warnings.CategoryRateLimit,
			Message:  "--verify-shas running anonymously; 60 API calls/hour, set --github-token for realistic limits",
		})
	}

	var r io.Reader

	if useStdin {
		r = os.Stdin
	} else if len(args) == 1 {
		f, err := os.Open(args[0])
		if err != nil {
			return fmt.Errorf("opening file: %w", err)
		}
		defer f.Close()
		r = f
	} else {
		return fmt.Errorf("provide a file argument or use --stdin")
	}

	var abom model.ABOM
	if err := json.NewDecoder(r).Decode(&abom); err != nil {
		return fmt.Errorf("parsing ABOM JSON: %w", err)
	}

	db := advisory.NewDatabase(advisory.LoadOptions{
		Offline: offline,
		NoCache: noCache,
		Quiet:   quiet,
		Token:   githubToken,
	})
	db.CheckAll(&abom)

	abom.CollectActions()

	if verifyShas {
		if !quiet {
			fmt.Fprintln(os.Stderr, "Verifying pinned SHAs against upstream refs...")
		}
		resolver.VerifyABOMShas(&abom, resolver.NewGitHubSHAVerifier(githubToken), col)
	}

	if abom.Summary.Compromised == 0 {
		fmt.Println("No compromised actions found.")
	} else {
		fmt.Fprintf(os.Stderr, "Found %d compromised action(s):\n\n", abom.Summary.Compromised)
		for _, ref := range abom.Actions {
			if ref.Compromised {
				fmt.Fprintf(os.Stdout, "  %s  (%s)\n", ref.Raw, ref.Advisory)
				for _, by := range ref.ReferencedBy {
					fmt.Fprintf(os.Stdout, "    referenced by: %s\n", by)
				}
			}
		}
	}

	if col.Count() > 0 {
		col.Print(os.Stderr)
	}

	if abom.Summary.Compromised > 0 {
		return &exitError{code: 1}
	}
	if failOnWarnings && col.Count() > 0 {
		return &exitError{code: 2}
	}
	return nil
}
