package warnings

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestCollector_EmptyByDefault(t *testing.T) {
	c := &Collector{}
	if c.Count() != 0 {
		t.Errorf("Count() = %d, want 0", c.Count())
	}
	if len(c.All()) != 0 {
		t.Errorf("All() length = %d, want 0", len(c.All()))
	}
}

func TestCollector_EmitAndCount(t *testing.T) {
	c := &Collector{}
	c.Emit(Warning{Category: CategorySHAUnreachable, Subject: "actions/checkout@abc123", Message: "not in upstream refs"})
	c.Emit(Warning{Category: CategoryRateLimit, Message: "rate limited"})

	if c.Count() != 2 {
		t.Fatalf("Count() = %d, want 2", c.Count())
	}

	all := c.All()
	if all[0].Category != CategorySHAUnreachable {
		t.Errorf("first category = %s, want %s", all[0].Category, CategorySHAUnreachable)
	}
	if all[1].Category != CategoryRateLimit {
		t.Errorf("second category = %s, want %s", all[1].Category, CategoryRateLimit)
	}
}

func TestCollector_Print(t *testing.T) {
	c := &Collector{}
	c.Emit(Warning{
		Category: CategorySHAUnreachable,
		Subject:  "actions/checkout@abc123",
		Message:  "SHA not reachable from actions/checkout refs",
	})
	c.Emit(Warning{
		Category: CategoryRateLimit,
		Message:  "rate limited by GitHub",
		Err:      errors.New("403 Forbidden"),
	})

	var buf bytes.Buffer
	c.Print(&buf)
	out := buf.String()

	if !strings.Contains(out, "sha-unreachable") {
		t.Errorf("output missing category: %q", out)
	}
	if !strings.Contains(out, "actions/checkout@abc123") {
		t.Errorf("output missing subject: %q", out)
	}
	if !strings.Contains(out, "rate-limit") {
		t.Errorf("output missing rate-limit category: %q", out)
	}
	if !strings.Contains(out, "403 Forbidden") {
		t.Errorf("output missing wrapped error: %q", out)
	}

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 lines, got %d: %q", len(lines), out)
	}
}

func TestCollector_PrintEmpty(t *testing.T) {
	c := &Collector{}
	var buf bytes.Buffer
	c.Print(&buf)
	if buf.Len() != 0 {
		t.Errorf("empty collector should produce no output, got %q", buf.String())
	}
}
