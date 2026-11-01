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

func TestOutputFailureNeverHidesCriticalFindings(t *testing.T) {
	if got := failedOutput(2); got != 2 {
		t.Errorf("critical findings must keep exit 2, got %d", got)
	}
	for _, code := range []int{0, 1, 3} {
		if got := failedOutput(code); got != 74 {
			t.Errorf("failedOutput(%d) = %d, want 74", code, got)
		}
	}
}
