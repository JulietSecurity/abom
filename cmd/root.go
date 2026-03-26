package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	githubToken string
	quiet       bool
	noCache     bool
	offline     bool
	version     = "dev"
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
  abom check abom.json                 Check a saved ABOM against advisories`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&githubToken, "github-token", os.Getenv("GITHUB_TOKEN"), "GitHub token for API requests")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Suppress progress output")
	rootCmd.PersistentFlags().BoolVar(&noCache, "no-cache", false, "Force fresh advisory fetch, skip cache")
	rootCmd.PersistentFlags().BoolVar(&offline, "offline", false, "Skip advisory fetch, use built-in data only")
	rootCmd.Version = version
}
