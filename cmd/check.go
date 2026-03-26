package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/julietsecurity/abom/pkg/advisory"
	"github.com/julietsecurity/abom/pkg/model"
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

	if abom.Summary.Compromised == 0 {
		fmt.Println("No compromised actions found.")
		return nil
	}

	fmt.Fprintf(os.Stderr, "Found %d compromised action(s):\n\n", abom.Summary.Compromised)
	for _, ref := range abom.Actions {
		if ref.Compromised {
			fmt.Fprintf(os.Stdout, "  %s  (%s)\n", ref.Raw, ref.Advisory)
			for _, by := range ref.ReferencedBy {
				fmt.Fprintf(os.Stdout, "    referenced by: %s\n", by)
			}
		}
	}

	// Exit code 1 if compromised actions found
	os.Exit(1)
	return nil
}
