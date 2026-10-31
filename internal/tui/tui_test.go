package tui

import (
	"context"
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"ubuntu-sys-audit/internal/checks"
	"ubuntu-sys-audit/internal/model"
)

// sampleReport keeps CJK text on purpose: file names and process names on a
// host can hold any language, and they must not break the layout.
func sampleReport() *model.Report {
	r := &model.Report{
		Host: model.Host{Hostname: "web-01", OSName: "Ubuntu", OSVersion: "22.04", Kernel: "5.15.0-91-generic", IsRoot: true},
	}
	for i, sev := range model.AllSeverities {
		for j := range 12 {
			r.Findings = append(r.Findings, model.Finding{
				ID:          fmt.Sprintf("x.%d.%d", i, j),
				Category:    model.Categories[(i+j)%len(model.Categories)],
				Severity:    sev,
				Title:       fmt.Sprintf("nginx：第 %d 則安全公告未修補，這是一段很長的標題用來測試中文寬度的截斷行為 %d", j, j),
				Detail:      strings.Repeat("這段說明文字很長，用來測試自動換行。", 12),
				Remediation: "sudo apt update && sudo apt install --only-upgrade nginx nginx-core nginx-common",
				Evidence: []string{
					"USN-6723-1  2024-04-08  [high]  nginx vulnerabilities  CVE-2024-24989 CVE-2024-24990",
					strings.Repeat("averylongtokenwithoutanyspaces", 12),
					"/var/www/html/上傳/中文檔名.php（直接執行 HTTP 請求內容）",
				},
				Refs: []string{"https://ubuntu.com/security/notices/USN-6723-1"},
			})
		}
	}
	r.Finalize()
	return r
}

func newResultsModel(t *testing.T, w, h int) *Model {
	t.Helper()
	m := New(context.Background(), checks.Options{Version: "test"})
	m.report = sampleReport()
	m.phase = phaseResults
	m.buildCategories()
	m.applyFilter()
	m.Update(tea.WindowSizeMsg{Width: w, Height: h})
	return m
}

func assertFits(t *testing.T, content string, w, h int) {
	t.Helper()
	lines := strings.Split(content, "\n")
	if len(lines) > h {
		t.Errorf("%dx%d: rendered %d lines, overflows the terminal", w, h, len(lines))
	}
	for i, l := range lines {
		if got := lipgloss.Width(l); got > w {
			t.Errorf("%dx%d: line %d is %d cells wide: %q", w, h, i, got, ansi.Strip(l))
			return
		}
	}
}

var sizes = [][2]int{{minWidth, minHeight}, {60, 20}, {80, 24}, {100, 30}, {109, 30}, {110, 30}, {120, 40}, {160, 50}, {240, 70}}

// Layout tests set IsRoot themselves. The warning line only exists for non root
// users, so relying on whoever runs the tests would hide half the layouts.
func TestResultsLayoutFitsEveryTerminalSize(t *testing.T) {
	for _, root := range []bool{true, false} {
		for _, s := range sizes {
			m := newResultsModel(t, s[0], s[1])
			m.host.IsRoot = root
			assertFits(t, m.viewResults(), s[0], s[1])
			for range 20 {
				m.handleKey(tea.KeyPressMsg{Code: 'j', Text: "j"})
			}
			assertFits(t, m.viewResults(), s[0], s[1])
		}
	}
}

func TestScanLayoutFitsEveryTerminalSize(t *testing.T) {
	var findings []model.Finding
	for _, sev := range model.AllSeverities {
		for range 120 {
			findings = append(findings, model.Finding{Severity: sev, Title: strings.Repeat("A very long critical alert title ", 10)})
		}
	}
	for _, root := range []bool{true, false} {
		for _, s := range sizes {
			m := New(context.Background(), checks.Options{Version: "test"})
			m.host.IsRoot = root
			m.Update(tea.WindowSizeMsg{Width: s[0], Height: s[1]})
			m.applyEvent(checks.Event{Index: 3, Done: false})
			m.applyEvent(checks.Event{Index: 0, Done: true, Findings: findings})
			assertFits(t, m.viewScan(), s[0], s[1])
		}
	}
}

func TestCursorStaysVisibleAndInBounds(t *testing.T) {
	m := newResultsModel(t, 120, 30)
	total := len(m.visible)
	h := m.listHeight()
	for range total + 10 {
		m.moveCursor("down")
		if m.cursor < m.listTop || m.cursor >= m.listTop+h {
			t.Fatalf("cursor %d outside window top=%d h=%d", m.cursor, m.listTop, h)
		}
	}
	if m.cursor != total-1 {
		t.Errorf("cursor should stop at the last row, got %d of %d", m.cursor, total)
	}
	m.moveCursor("home")
	if m.cursor != 0 || m.listTop != 0 {
		t.Errorf("home: cursor=%d top=%d", m.cursor, m.listTop)
	}
}

func TestFilterCategoryAndSearch(t *testing.T) {
	m := newResultsModel(t, 120, 30)
	all := len(m.visible)
	m.filter = filterUrgent
	m.applyFilter()
	if len(m.visible) != 24 {
		t.Errorf("urgent filter: want 24, got %d", len(m.visible))
	}
	for _, i := range m.visible {
		if m.report.Findings[i].Severity > model.High {
			t.Fatalf("filter let through %v", m.report.Findings[i].Severity)
		}
	}
	m.filter = filterAll
	m.catIdx = 1
	m.applyFilter()
	if len(m.visible) == 0 || len(m.visible) >= all {
		t.Errorf("category filter: %d of %d", len(m.visible), all)
	}
	m.catIdx = 0
	m.query = "USN-6723-1"
	m.applyFilter()
	if len(m.visible) != all {
		t.Errorf("search should match evidence: %d of %d", len(m.visible), all)
	}
	m.query = "no-such-thing"
	m.applyFilter()
	if len(m.visible) != 0 || m.current() != nil {
		t.Errorf("search with no match: %d", len(m.visible))
	}
	assertFits(t, m.viewResults(), 120, 30)
}

func TestSkippedCategoryNeverLooksPassed(t *testing.T) {
	m := newResultsModel(t, 120, 30)
	m.report.Findings = []model.Finding{
		{Category: model.CatCVE, Severity: model.Skipped, Title: "CVE check"},
		{Category: model.CatWeb, Severity: model.OK, Title: "nginx not found"},
		{Category: model.CatWeb, Severity: model.Skipped, Title: "PHP check"},
		{Category: model.CatSSH, Severity: model.OK, Title: "ok"},
		{Category: model.CatNetwork, Severity: model.Skipped},
		{Category: model.CatNetwork, Severity: model.High},
	}
	want := map[model.Category]model.Severity{
		model.CatCVE: model.Skipped, model.CatWeb: model.Skipped, model.CatSSH: model.OK, model.CatNetwork: model.High,
	}
	for cat, sev := range want {
		if _, got := m.categorySummary(cat); got != sev {
			t.Errorf("%s: symbol severity %v, want %v", cat, got, sev)
		}
	}
}

func TestSelectedCategoryTabStaysVisibleOnNarrowTerminals(t *testing.T) {
	for _, width := range []int{minWidth, 80, 100} {
		m := newResultsModel(t, width, 24)
		for i, cat := range m.cats {
			m.catIdx = i + 1
			tabs := m.renderCategoryTabs()
			if !strings.Contains(ansi.Strip(tabs), cat.Label()) {
				t.Errorf("width %d: selected tab %q not visible in %q", width, cat.Label(), ansi.Strip(tabs))
			}
			if got := lipgloss.Width(tabs); got > width {
				t.Errorf("width %d: tabs are %d cells wide", width, got)
			}
		}
	}
}

func TestSmallTerminalShowsMessage(t *testing.T) {
	m := New(context.Background(), checks.Options{Version: "test"})
	m.Update(tea.WindowSizeMsg{Width: 40, Height: 10})
	if !strings.Contains(m.View().Content, "too small") {
		t.Errorf("expected too small message, got %q", m.View().Content)
	}
}
