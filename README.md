<p align="center">
  <img src=".github/assets/abom-logo.svg" alt="abom logo" width="400">
</p>

<p align="center">
  <b>Actions Bill of Materials</b> — map your GitHub Actions supply chain
</p>

<p align="center">
  <a href="https://github.com/JulietSecurity/abom/actions/workflows/ci.yml"><img src="https://github.com/JulietSecurity/abom/actions/workflows/ci.yml/badge.svg" alt="Build"></a>
  <a href="https://goreportcard.com/report/github.com/JulietSecurity/abom"><img src="https://goreportcard.com/badge/github.com/JulietSecurity/abom" alt="Go Report Card"></a>
  <a href="https://github.com/JulietSecurity/abom/releases/latest"><img src="https://img.shields.io/github/v/release/JulietSecurity/abom" alt="GitHub release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache 2.0"></a>
</p>

---

SBOMs exist for your application dependencies. **ABOMs should exist for your CI/CD pipelines.**

`abom` recursively resolves every GitHub Action in your workflows — including actions nested inside composite actions, reusable workflows, and actions that silently embed tools like Trivy in their own code — and builds a complete dependency tree.

```
$ abom scan . --check
WORKFLOW                  STEP                      ACTION                             REF  STATUS
.github/workflows/ci.yml  Checkout v4               actions/checkout                   v4   tag
.github/workflows/ci.yml  Setup Node.js             actions/setup-node                 v4   tag
.github/workflows/ci.yml  Set up Docker Buildx      docker/setup-buildx-action         v3   tag
.github/workflows/ci.yml  Scan for vulnerabilities  crazy-max/ghaction-container-scan  v3   COMPROMISED (ABOM-2026-001 (detected via action inputs))

Compromised actions found: 1 (1 direct, 0 transitive)
```

> **grep can't find this.** The workflow never mentions `trivy-action`. But `crazy-max/ghaction-container-scan` downloads and runs Trivy internally. `abom` detects it by analyzing the action's metadata.

## Why this exists

The [Trivy supply chain compromise (CVE-2026-33634)](https://nvd.nist.gov/vuln/detail/CVE-2026-33634) exposed a blind spot: organizations grepped their workflows for `trivy-action` and found nothing — while compromised code ran in their pipelines through transitive and embedded dependencies.

Every post-incident guide from CrowdStrike, Wiz, Snyk, and Microsoft tells you to grep your workflows. **None of them address transitive action dependencies.**

`abom` was built to close that gap.

*We hope the Trivy project recovers quickly — this tool exists to address a gap in incident response, not to pile on. Supply chain attacks can happen to any project.*

## Features

- **Recursive resolution** — follows composite actions and reusable workflows through the full dependency chain
- **Tool wrapper detection** — identifies actions that embed known tools (Trivy, Grype, Snyk, etc.) by analyzing `action.yml` inputs and descriptions
- **Remote scanning** — scan any public GitHub repo without cloning: `abom scan github.com/org/repo`
- **Advisory database** — built-in + auto-updated database of known-compromised actions
- **Standard BOM formats** — output as CycloneDX 1.5 or SPDX 2.3 for integration with Dependency-Track, Grype, and other tooling
- **SHA verification** — optionally verify that pinned SHAs are actually reachable from the upstream repo, catching fork-sourced and force-pushed-away commits (`--verify-shas`)
- **CI gate** — exits non-zero when compromised actions are found or (with `--fail-on-warnings`) when any advisory warning is emitted
- **Fast** — caches resolved actions locally, uses `raw.githubusercontent.com` to avoid API rate limits

## Installation

**Homebrew:**
```bash
brew install JulietSecurity/tap/abom
```

**Go:**
```bash
go install github.com/julietsecurity/abom@latest
```

**Binary releases:**

Download prebuilt binaries for Linux, macOS, and Windows from [GitHub Releases](https://github.com/JulietSecurity/abom/releases).

## The basics

Scan a repository and see every action in your supply chain:

```bash
# Local repo
abom scan .

# Remote repo — no clone needed
abom scan github.com/your-org/your-repo
```

Check for known-compromised actions:

```bash
abom scan . --check
```

Generate standard BOM formats:

```bash
# CycloneDX 1.5 — for Dependency-Track, Grype, etc.
abom scan . -o cyclonedx-json

# SPDX 2.3 — for compliance tooling
abom scan . -o spdx-json

# Native JSON — full dependency tree with metadata
abom scan . -o json
```

Use as a CI gate:

```yaml
- name: Check Actions supply chain
  run: abom scan . --check
```

Block on fork-sourced SHA pins as well:

```yaml
- name: Check Actions supply chain
  run: abom scan . --check --verify-shas --fail-on-warnings
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Verifying pinned SHAs

Pinning an action to a SHA (e.g. `actions/checkout@a1b2c3...`) is the recommended defense against tag-swap attacks. But GitHub's object store is shared across a repo and its forks — so a SHA that exists only on a fork (or was force-pushed out of the upstream's history) will still resolve successfully when a workflow runs. The pin protects you from tag mutation, but not from a commit that was never in the upstream's ref graph.

`--verify-shas` hits the GitHub commits API for each SHA-pinned reference and emits a warning when the SHA isn't reachable from the claimed repo's refs. It doesn't change resolution behavior — ABOM still builds the same dependency tree GitHub would — it just surfaces the discrepancy.

```bash
abom scan . --verify-shas --github-token $GITHUB_TOKEN
```

Combine with `--fail-on-warnings` to block CI on the finding:

```bash
abom scan . --verify-shas --fail-on-warnings --github-token $GITHUB_TOKEN
```

**What a warning means:** the SHA is not reachable from `owner/repo`'s refs. That may be a fork-only commit, a force-pushed-away commit, or a mistaken pin. It does **not** necessarily mean the SHA was tampered with.

**Exit codes:** `0` clean, `1` compromised action (or runtime error), `2` warnings emitted with `--fail-on-warnings`. When both conditions hold, exit `1` wins.

**Rate limit caveat:** `--verify-shas` makes an extra API call per unique SHA. Anonymous requests are capped at 60/hour — set `--github-token` (or `GITHUB_TOKEN`) for a realistic 5000/hour budget.

## How detection works

`abom` finds compromised dependencies through three layers that grep will never reach:

| Layer | What it catches | How |
|-------|----------------|-----|
| **Direct** | `uses: aquasecurity/trivy-action@v0.20.0` | Parses workflow YAML |
| **Transitive** | Composite action A calls action B which calls `trivy-action` | Fetches and parses `action.yml` recursively |
| **Embedded** | `crazy-max/ghaction-container-scan` has a `trivy_version` input | Scans action metadata for known tool signatures |

## Output formats

| Format | Flag | Use case |
|--------|------|----------|
| Table | `-o table` | Human-readable dependency tree (default) |
| JSON | `-o json` | Native ABOM format for automation |
| CycloneDX 1.5 | `-o cyclonedx-json` | Dependency-Track, Grype, standard BOM tooling |
| SPDX 2.3 | `-o spdx-json` | Compliance, license scanning, SBOM aggregation |

## Advisory database

`abom --check` compares your ABOM against known-compromised actions:

- **Built-in** — a snapshot ships with every release. Works fully offline.
- **Auto-updated** — fetches the latest data from [`JulietSecurity/abom-advisories`](https://github.com/JulietSecurity/abom-advisories) at runtime.
- **Community-curated** — anyone can submit a PR to add a new advisory.

Current advisories:
| ID | CVE | Description |
|----|-----|-------------|
| ABOM-2026-001 | CVE-2026-33634 | Trivy GitHub Actions supply chain compromise |

## All flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--output` | `-o` | Output format: `table`, `json`, `cyclonedx-json`, `spdx-json` | `table` |
| `--file` | `-f` | Write output to file instead of stdout | stdout |
| `--check` | | Flag known-compromised actions | `false` |
| `--depth` | `-d` | Max recursion depth for transitive deps | `10` |
| `--verify-shas` | | Verify pinned SHAs are reachable from upstream repo refs | `false` |
| `--fail-on-warnings` | | Exit `2` if any warnings were emitted | `false` |
| `--github-token` | | GitHub token for API requests (also reads `GITHUB_TOKEN`) | |
| `--no-network` | | Skip resolving transitive dependencies (local parsing only) | `false` |
| `--offline` | | Use built-in advisory data only, skip remote fetch | `false` |
| `--no-cache` | | Force fresh advisory database fetch | `false` |
| `--quiet` | `-q` | Suppress progress output, only print results | `false` |

## Contributing

We welcome contributions. If you discover a compromised action or a wrapper that `abom` should detect:

- **Advisory data** — submit a PR to [`JulietSecurity/abom-advisories`](https://github.com/JulietSecurity/abom-advisories)
- **Tool detection** — add tool signatures in [`pkg/parser/action.go`](pkg/parser/action.go)
- **Bug reports and features** — [open an issue](https://github.com/JulietSecurity/abom/issues)

## License

`abom` is released under the [Apache 2.0 License](LICENSE).

---

<p align="center">
  <b>Built and maintained by <a href="https://juliet.sh">Juliet Security</a></b>
  <br>
  <a href="https://juliet.sh">Website</a> · <a href="https://github.com/JulietSecurity">GitHub</a> · <a href="mailto:contact@juliet.sh">Contact</a>
</p>
