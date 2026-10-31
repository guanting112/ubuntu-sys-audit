package model

import (
	"strings"
	"testing"
)

func TestSanitizeNeutralizesTerminalEscapes(t *testing.T) {
	cases := map[string]string{
		"plain name":            "plain name",
		"evil\x1b[2Jname":       `evil\x1b[2Jname`,
		"\x1b]52;c;AAAA\x07":    `\x1b]52;c;AAAA\x07`,
		"a‮b":                   `a\x202eb`,
		"中文路徑":                  "中文路徑",
		"\u009b31m":             `\x9b31m`,
		"\x9b31m":               "\\ufffd31m",
		"keep\ttabs\nand lines": "keep\ttabs\nand lines",
		"bad\xffbyte":           "bad\\ufffdbyte",
	}
	for in, want := range cases {
		if got := Sanitize(in); got != want {
			t.Errorf("Sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRedactMasksCredentials(t *testing.T) {
	cases := []struct{ in, leak string }{
		{"mysql --password=hunter2 -u root", "hunter2"},
		{"app --token abc123def", "abc123def"},
		{"curl https://bob:s3cret@example.com/x", "s3cret"},
		{"API_KEY=zzzyyy ./run", "zzzyyy"},
		{`password: "two words"`, "two words"},
		{"root:$6$abcdefgh$AAAABBBBCCCCDDDD:19000", "AAAABBBBCCCCDDDD"},
		{"root:$y$j9T$saltsalt$hashhashhash:19000", "hashhashhash"},
	}
	for _, c := range cases {
		if got := Redact(c.in); strings.Contains(got, c.leak) {
			t.Errorf("Redact(%q) = %q still contains %q", c.in, got, c.leak)
		}
	}
	for _, benign := range []string{"nginx: worker process", "www-data ALL=(ALL) NOPASSWD:ALL", "PasswordAuthentication no"} {
		if got := Redact(benign); got != benign {
			t.Errorf("Redact changed benign text: %q -> %q", benign, got)
		}
	}
	if got := Redact("DB_PASSWORD=hunter2 ./app"); strings.Contains(got, "hunter2") {
		t.Errorf("underscore prefixed keyword leaked: %q", got)
	}
}

func TestCleanFindingFlattensSingleLineFields(t *testing.T) {
	f := CleanFinding(Finding{
		Title:    "x\ny\x1b[31m",
		Evidence: []string{"a\nb"},
	})
	if strings.Contains(f.Title, "\n") || strings.Contains(f.Title, "\x1b") {
		t.Errorf("title not flattened: %q", f.Title)
	}
	if strings.Contains(f.Evidence[0], "\n") {
		t.Errorf("evidence not flattened: %q", f.Evidence[0])
	}
}

func TestExitCode(t *testing.T) {
	r := Report{Findings: []Finding{{Severity: Info}, {Severity: OK}, {Severity: Skipped}}}
	r.Finalize()
	if r.ExitCode() != 0 {
		t.Errorf("info/ok/skipped should exit 0, got %d", r.ExitCode())
	}
	r.Findings = append(r.Findings, Finding{Severity: Medium})
	r.Finalize()
	if r.ExitCode() != 1 {
		t.Errorf("medium should exit 1, got %d", r.ExitCode())
	}
	r.Findings = append(r.Findings, Finding{Severity: High})
	r.Finalize()
	if r.ExitCode() != 2 {
		t.Errorf("high should exit 2, got %d", r.ExitCode())
	}
	if r.Findings[0].Severity != High {
		t.Errorf("findings not sorted by severity: %+v", r.Findings[0])
	}
}
