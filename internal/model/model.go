// Package model holds the report data structures shared by the checks, the
// TUI and the text/JSON writers.
package model

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
)

// Severity ranks a finding. Lower numeric value sorts first.
type Severity int

const (
	Critical Severity = iota
	High
	Medium
	Info
	OK
	Skipped
)

var severityKeys = []string{"critical", "high", "medium", "info", "ok", "skipped"}
var severityLabels = []string{"Critical", "High", "Medium", "Info", "Passed", "Not checked"}

// AllSeverities lists severities in display order.
var AllSeverities = []Severity{Critical, High, Medium, Info, OK, Skipped}

func (s Severity) String() string { return severityKeys[s] }

// Label returns the display name.
func (s Severity) Label() string { return severityLabels[s] }

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// Category groups findings.
type Category string

const (
	CatSystem      Category = "system"
	CatAccounts    Category = "accounts"
	CatSSH         Category = "ssh"
	CatNetwork     Category = "network"
	CatProcess     Category = "process"
	CatIntegrity   Category = "integrity"
	CatPersistence Category = "persistence"
	CatFilesystem  Category = "filesystem"
	CatPackages    Category = "packages"
	CatCVE         Category = "cve"
	CatWeb         Category = "web"
)

// Categories lists categories in display order.
var Categories = []Category{
	CatCVE, CatWeb, CatNetwork, CatProcess, CatIntegrity, CatPersistence,
	CatAccounts, CatSSH, CatFilesystem, CatPackages, CatSystem,
}

var categoryLabels = map[Category]string{
	CatSystem:      "System",
	CatAccounts:    "Accounts",
	CatSSH:         "SSH",
	CatNetwork:     "Network",
	CatProcess:     "Processes",
	CatIntegrity:   "Integrity",
	CatPersistence: "Persistence",
	CatFilesystem:  "Filesystem",
	CatPackages:    "Packages",
	CatCVE:         "CVE",
	CatWeb:         "Web",
}

// Label returns the display name.
func (c Category) Label() string {
	if l, ok := categoryLabels[c]; ok {
		return l
	}
	return string(c)
}

// Finding is a single result. Every string field is untrusted until passed
// through Clean, because it can carry process names, file names or config
// lines controlled by whoever has access to the host.
type Finding struct {
	ID          string   `json:"id"`
	Category    Category `json:"category"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Detail      string   `json:"detail,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Refs        []string `json:"refs,omitempty"`
	Focus       bool     `json:"focus,omitempty"`
	// Requested marks a skipped check the operator turned off with a flag, which
	// does not make the scan incomplete.
	Requested bool `json:"requested,omitempty"`
}

// Host describes the scanned machine.
type Host struct {
	Hostname    string `json:"hostname"`
	OSName      string `json:"os_name"`
	OSVersion   string `json:"os_version"`
	Codename    string `json:"codename"`
	Kernel      string `json:"kernel"`
	Arch        string `json:"arch"`
	UptimeSec   int64  `json:"uptime_seconds"`
	IsRoot      bool   `json:"is_root"`
	InContainer bool   `json:"in_container"`
}

// CheckResult records how a single check ran.
type CheckResult struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	DurationMS int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
}

// InventoryItem is one entry in the installed software summary.
type InventoryItem struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  string `json:"source"`
}

// Summary counts findings per severity.
type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Info     int `json:"info"`
	OK       int `json:"ok"`
	Skipped  int `json:"skipped"`
}

// Count returns the count for a severity.
func (s Summary) Count(sev Severity) int {
	switch sev {
	case Critical:
		return s.Critical
	case High:
		return s.High
	case Medium:
		return s.Medium
	case Info:
		return s.Info
	case OK:
		return s.OK
	default:
		return s.Skipped
	}
}

// Report is the complete scan result.
type Report struct {
	Tool       string          `json:"tool"`
	Version    string          `json:"version"`
	ScannedAt  time.Time       `json:"scanned_at"`
	DurationMS int64           `json:"duration_ms"`
	Host       Host            `json:"host"`
	Summary    Summary         `json:"summary"`
	Incomplete bool            `json:"incomplete"`
	Findings   []Finding       `json:"findings"`
	Inventory  []InventoryItem `json:"inventory,omitempty"`
	Checks     []CheckResult   `json:"checks"`
}

// Finalize sorts findings and recomputes the summary.
func (r *Report) Finalize() {
	SortFindings(r.Findings)
	r.Summary = Summary{}
	r.Incomplete = false
	for _, f := range r.Findings {
		if f.Severity == Skipped && !f.Requested {
			r.Incomplete = true
		}
		switch f.Severity {
		case Critical:
			r.Summary.Critical++
		case High:
			r.Summary.High++
		case Medium:
			r.Summary.Medium++
		case Info:
			r.Summary.Info++
		case OK:
			r.Summary.OK++
		default:
			r.Summary.Skipped++
		}
	}
}

// SortFindings orders by severity, then focus items, then category and title.
func SortFindings(fs []Finding) {
	order := map[Category]int{}
	for i, c := range Categories {
		order[c] = i
	}
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity != b.Severity {
			return a.Severity < b.Severity
		}
		if a.Focus != b.Focus {
			return a.Focus
		}
		if order[a.Category] != order[b.Category] {
			return order[a.Category] < order[b.Category]
		}
		return a.Title < b.Title
	})
}

// ExitCode maps the report to a process exit code: 2 for critical or high
// findings, 3 when something could not be checked, 1 for medium findings and 0
// otherwise. An incomplete scan outranks medium findings because a low code must
// never suggest a host is fine when part of the scan did not run.
func (r *Report) ExitCode() int {
	switch {
	case r.Summary.Critical > 0 || r.Summary.High > 0:
		return 2
	case r.Incomplete:
		return 3
	case r.Summary.Medium > 0:
		return 1
	}
	return 0
}

const maxLineRunes = 600

// keywordSecret matches KEY=value and KEY: value for anything ending in a secret
// sounding word, so PGPASSWORD=x and DB_PASS=x are covered. The leading class
// keeps a path like /etc/passwd: from counting as a key.
var keywordSecret = regexp.MustCompile(`(?i)(^|[^a-z0-9_/.-])([a-z0-9_-]*(?:pass(?:word|wd)?|pwd|token|secret|api[_-]?key|access[_-]?key)["']?[ \t]*[=:][ \t]*)("[^"]*"|'[^']*'|[^\s&;,]+)`)

// secretPatterns cover credentials passed the way common command line tools take
// them. Each keeps group 1 and masks group 2.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(--?(?:pass(?:word|wd)?|token|secret|api-?key)[ \t]+)(\S+)`),
	regexp.MustCompile(`((?:^|[\s;|&/])(?:mysql|mysqldump|mysqladmin|mariadb|mariadb-dump)\b[^|;&]*\s-p)([^\s-]\S*)`),
	regexp.MustCompile(`(sshpass\s+-p[ \t]*)(\S+)`),
	regexp.MustCompile(`(redis-cli\b[^|;&]*\s-a[ \t]+)(\S+)`),
	regexp.MustCompile(`((?:curl|wget)\b[^|;&]*\s(?:-u|--user)[ \t=]+[^\s:]+:)(\S+)`),
	regexp.MustCompile(`(?i)(\b(?:bearer|basic)[ \t]+)([a-z0-9._~+/=-]{6,})`),
}

var (
	urlPassword = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+:)([^\s/@]+)(@)`)
	cryptHash   = regexp.MustCompile(`(\$(?:1|2[aby]|5|6|y|gy|7)\$)[./A-Za-z0-9$,=-]{8,}`)
)

// Redact masks values that look like credentials. Command lines and config lines
// end up in reports people pass around, so they should not carry secrets. It
// covers common forms only, so reports still need handling with care.
func Redact(s string) string {
	s = keywordSecret.ReplaceAllStringFunc(s, func(match string) string {
		m := keywordSecret.FindStringSubmatch(match)
		// sudoers' NOPASSWD:ALL is a setting worth reading, not a secret.
		if strings.HasPrefix(strings.ToLower(m[2]), "nopasswd") {
			return match
		}
		return m[1] + m[2] + "***"
	})
	for _, re := range secretPatterns {
		s = re.ReplaceAllString(s, "${1}***")
	}
	s = urlPassword.ReplaceAllString(s, "${1}***${3}")
	return cryptHash.ReplaceAllString(s, "${1}***")
}

// Sanitize makes an untrusted string safe to print on a terminal: control
// characters, escape sequences and bidi overrides become visible \xNN text so
// a hostile file or process name cannot drive the operator's terminal.
func Sanitize(s string) string {
	if !strings.ContainsFunc(s, unsafeRune) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r == unicode.ReplacementChar:
			b.WriteString(`\ufffd`)
		case unsafeRune(r):
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func unsafeRune(r rune) bool {
	if r == '\n' || r == '\t' {
		return false
	}
	if r == unicode.ReplacementChar || r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
		return true
	}
	return (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) ||
		r == 0x200e || r == 0x200f || r == 0x061c
}

// Clean redacts, sanitizes and truncates a line of evidence.
func Clean(s string) string {
	s = Sanitize(Redact(s))
	if r := []rune(s); len(r) > maxLineRunes {
		s = string(r[:maxLineRunes]) + "…"
	}
	return s
}

// CleanFinding applies Clean to every text field of a finding.
func CleanFinding(f Finding) Finding {
	f.Title = strings.ReplaceAll(Clean(f.Title), "\n", " ")
	f.Detail = Clean(f.Detail)
	f.Remediation = Clean(f.Remediation)
	for i, e := range f.Evidence {
		f.Evidence[i] = strings.ReplaceAll(Clean(e), "\n", " ")
	}
	return f
}
