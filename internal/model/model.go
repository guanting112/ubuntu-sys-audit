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
var severityLabels = []string{"嚴重", "高", "中", "資訊", "通過", "未檢查"}

// AllSeverities lists severities in display order.
var AllSeverities = []Severity{Critical, High, Medium, Info, OK, Skipped}

func (s Severity) String() string { return severityKeys[s] }

// Label returns the Traditional Chinese display name.
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
	CatSystem:      "系統",
	CatAccounts:    "帳號",
	CatSSH:         "SSH",
	CatNetwork:     "網路",
	CatProcess:     "程序",
	CatIntegrity:   "完整性",
	CatPersistence: "持久化",
	CatFilesystem:  "檔案",
	CatPackages:    "套件",
	CatCVE:         "CVE",
	CatWeb:         "Web",
}

// Label returns the Traditional Chinese display name.
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
	Findings   []Finding       `json:"findings"`
	Inventory  []InventoryItem `json:"inventory,omitempty"`
	Checks     []CheckResult   `json:"checks"`
}

// Finalize sorts findings and recomputes the summary.
func (r *Report) Finalize() {
	SortFindings(r.Findings)
	r.Summary = Summary{}
	for _, f := range r.Findings {
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

// ExitCode maps the summary to a process exit code: 2 for critical or high
// findings, 1 for medium findings, 0 otherwise.
func (r *Report) ExitCode() int {
	switch {
	case r.Summary.Critical > 0 || r.Summary.High > 0:
		return 2
	case r.Summary.Medium > 0:
		return 1
	}
	return 0
}

const maxLineRunes = 600

var secretPatterns = []*regexp.Regexp{
	// The leading class requires a non letter before the keyword, so sudoers'
	// NOPASSWD:ALL stays readable while DB_PASSWORD=x is still masked.
	regexp.MustCompile(`(?i)((?:^|[^a-z])(?:pass(?:word|wd)?|pwd|token|secret|api[_-]?key|access[_-]?key)[ \t]*[=:][ \t]*)("[^"]*"|'[^']*'|[^\s&;,]+)`),
	regexp.MustCompile(`(?i)(--?(?:pass(?:word|wd)?|token|secret|api-?key)[ \t]+)(\S+)`),
	regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+:)([^\s/@]+)(@)`),
	regexp.MustCompile(`(\$(?:1|2[aby]|5|6|y|gy|7)\$)[./A-Za-z0-9$,=-]{8,}`),
}

// Redact masks values that look like credentials. Command lines and config
// lines end up in reports people pass around, so they must not carry secrets.
func Redact(s string) string {
	s = secretPatterns[0].ReplaceAllString(s, "${1}***")
	s = secretPatterns[1].ReplaceAllString(s, "${1}***")
	s = secretPatterns[2].ReplaceAllString(s, "${1}***${3}")
	s = secretPatterns[3].ReplaceAllString(s, "${1}***")
	return s
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
