package main

import (
	"os"
	"testing"

	"ubuntu-sys-audit/internal/model"
)

func TestDevNullIsNotATerminal(t *testing.T) {
	f, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isTerminal(f) {
		t.Error("/dev/null must not count as a terminal, or cron runs would try to open the TUI")
	}
}

func TestParseSeverity(t *testing.T) {
	if got, ok := parseSeverity("HIGH"); !ok || got != model.High {
		t.Errorf("HIGH: got %v ok=%v", got, ok)
	}
	if _, ok := parseSeverity("nope"); ok {
		t.Error("an unknown level must be rejected")
	}
}
