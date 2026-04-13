// Package warnings collects non-fatal diagnostics emitted during an abom run.
//
// Warnings are runtime signals (e.g. a pinned SHA that can't be verified
// against the upstream repo's refs), not part of the BOM artifact itself.
// They're printed to stderr and can optionally gate the exit code via
// --fail-on-warnings.
package warnings

import (
	"fmt"
	"io"
)

type Category string

const (
	CategorySHAUnreachable Category = "sha-unreachable"
	CategoryRateLimit      Category = "rate-limit"
)

type Warning struct {
	Category Category
	Subject  string
	Message  string
	Err      error
}

// Collector accumulates warnings during a run.
//
// The resolver is single-goroutine, so no mutex is needed. If concurrency is
// ever introduced in the resolve/verify path, this assumption must be
// revisited.
type Collector struct {
	warnings []Warning
}

func (c *Collector) Emit(w Warning) {
	c.warnings = append(c.warnings, w)
}

func (c *Collector) Count() int {
	return len(c.warnings)
}

func (c *Collector) All() []Warning {
	return c.warnings
}

// Print writes all collected warnings to w, one per line.
func (c *Collector) Print(w io.Writer) {
	for _, warn := range c.warnings {
		line := fmt.Sprintf("Warning [%s]", warn.Category)
		if warn.Subject != "" {
			line += " " + warn.Subject
		}
		if warn.Message != "" {
			line += ": " + warn.Message
		}
		if warn.Err != nil {
			line += " (" + warn.Err.Error() + ")"
		}
		fmt.Fprintln(w, line)
	}
}
