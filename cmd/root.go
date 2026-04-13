package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	githubToken    string
	quiet          bool
	noCache        bool
	offline        bool
	verifyShas     bool
	failOnWarnings bool
	version        = "dev"
)

var rootCmd = &cobra.Command{
	Use:   "abom",
	Short: "Actions Bill of Materials — map your GitHub Actions supply chain",
	Long: `Generate an Actions Bill of Materials (ABOM) from GitHub Actions workflows and detect compromised dependencies.

abom recursively resolves every GitHub Action in a repository's workflows,
builds a full dependency tree, and flags any action in the chain that
matches known-compromised components.

Quick start:
  abom scan .                          Scan local repo
  abom scan github.com/org/repo       Scan remote repo (no clone needed)
  abom scan . --check                  Flag compromised actions
  abom scan . -o json                  Output as JSON
  abom scan . -o cyclonedx-json        Output as CycloneDX 1.5
  abom scan . -o spdx-json             Output as SPDX 2.3
  abom check abom.json                 Check a saved ABOM against advisories

Exit codes:
  0  success
  1  compromised action found, or runtime error
  2  warnings emitted with --fail-on-warnings (and no compromised actions)`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// exitError signals a process exit code from RunE back to Execute(). Any
// diagnostic output should already have been written to stderr before this
// is returned — Execute() will not print anything additional for exitError.
type exitError struct {
	code int
}

func (e *exitError) Error() string { return fmt.Sprintf("exit code %d", e.code) }

// ExitCode returns the desired process exit code.
func (e *exitError) ExitCode() int { return e.code }

func Execute() {
	err := rootCmd.Execute()
	if err == nil {
		return
	}
	var ee *exitError
	if errors.As(err, &ee) {
		os.Exit(ee.code)
	}
	fmt.Fprintln(os.Stderr, "Error:", err.Error())
	os.Exit(1)
}

func init() {
	rootCmd.PersistentFlags().StringVar(&githubToken, "github-token", os.Getenv("GITHUB_TOKEN"), "GitHub token for API requests")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Suppress progress output")
	rootCmd.PersistentFlags().BoolVar(&noCache, "no-cache", false, "Force fresh advisory fetch, skip cache")
	rootCmd.PersistentFlags().BoolVar(&offline, "offline", false, "Skip advisory fetch, use built-in data only")
	rootCmd.PersistentFlags().BoolVar(&verifyShas, "verify-shas", false, "Verify SHA-pinned actions are reachable from upstream repo refs (requires --github-token for realistic rate limits; requires network)")
	rootCmd.PersistentFlags().BoolVar(&failOnWarnings, "fail-on-warnings", false, "Exit 2 if any warnings were emitted during the run")
	rootCmd.Version = version
}
