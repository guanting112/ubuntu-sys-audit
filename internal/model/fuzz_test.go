package model

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// assertTerminalSafe fails when out could still drive a terminal: invalid
// UTF-8, or a control character, escape or bidi override left in it.
func assertTerminalSafe(t *testing.T, in, out string) {
	t.Helper()
	if !utf8.ValidString(out) {
		t.Fatalf("output is not valid UTF-8: %q -> %q", in, out)
	}
	if i := strings.IndexFunc(out, unsafeRune); i >= 0 {
		r, _ := utf8.DecodeRuneInString(out[i:])
		t.Fatalf("%U left at byte %d: %q -> %q", r, i, in, out)
	}
}

// FuzzSanitize feeds Sanitize what a hostile file or process name may hold.
// Nothing that reaches the terminal may survive, and sanitizing twice must
// change nothing.
func FuzzSanitize(f *testing.F) {
	for _, s := range []string{
		"plain",
		"\x1b[31mred\x1b[0m",
		"a\x00b\x7f",
		"\xff\xfe\xe2\x80",
		"tab\tnew\nline\rreturn",
		"\xc2\x9b2J",
		string(rune(0x202e)) + "fdp.exe",
		string(rune(0xfffd)),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := Sanitize(s)
		assertTerminalSafe(t, s, out)
		if again := Sanitize(out); again != out {
			t.Fatalf("not idempotent: %q -> %q -> %q", s, out, again)
		}
	})
}

// FuzzClean adds redaction and truncation, which run before and after
// Sanitize, to the same checks.
func FuzzClean(f *testing.F) {
	for _, s := range []string{
		"password=hunter2",
		"https://user:secret@example.com/x",
		"root:$6$salt$hash:19000::::::",
		strings.Repeat("é", maxLineRunes+5),
		strings.Repeat("\x1b", maxLineRunes),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := Clean(s)
		assertTerminalSafe(t, s, out)
		if n := utf8.RuneCountInString(out); n > maxLineRunes+1 {
			t.Fatalf("%d runes, over the limit of %d plus the ellipsis", n, maxLineRunes)
		}
	})
}
