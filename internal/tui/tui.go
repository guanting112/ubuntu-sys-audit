// Package tui is the interactive front end, built on Bubble Tea and Lip Gloss.
package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"charm.land/bubbles/v2/progress"
	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/textinput"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/mattn/go-runewidth"

	"ubuntu-sys-audit/internal/checks"
	"ubuntu-sys-audit/internal/model"
	"ubuntu-sys-audit/internal/output"
)

func init() {
	// go-runewidth treats box drawing and bullets as double width when the
	// locale is zh_TW, which would break every border under a Taiwanese locale.
	runewidth.DefaultCondition.EastAsianWidth = false
}

// Below this size the two stacked panes no longer fit.
const (
	minWidth  = 60
	minHeight = 18
)

type phase int

const (
	phaseScan phase = iota
	phaseResults
)

type pane int

const (
	paneCategories pane = iota
	paneList
	paneDetail
)

type rowStatus int

const (
	rowPending rowStatus = iota
	rowRunning
	rowDone
)

type checkRow struct {
	check  checks.Check
	status rowStatus
	counts map[model.Severity]int
}

type filterMode int

const (
	filterAll filterMode = iota
	filterActionable
	filterUrgent
	filterSkipped
	filterCount
)

var filterLabels = map[filterMode]string{
	filterAll: "All", filterActionable: "Actionable (medium+)", filterUrgent: "Critical and high", filterSkipped: "Not checked",
}

type scanEventMsg checks.Event
type scanDoneMsg struct{ report *model.Report }
type tickMsg time.Time

// Model holds all TUI state.
type Model struct {
	ctx    context.Context
	cancel context.CancelFunc
	opts   checks.Options

	events chan checks.Event
	done   chan *model.Report

	st     styles
	width  int
	height int

	phase    phase
	started  time.Time
	elapsed  time.Duration
	rows     []checkRow
	finished int
	live     map[model.Severity]int
	alerts   []string
	host     model.Host
	spinner  spinner.Model
	progress progress.Model

	report  *model.Report
	aborted bool

	focus    pane
	cats     []model.Category
	catIdx   int
	filter   filterMode
	query    string
	searchOn bool
	search   textinput.Model
	visible  []int
	cursor   int
	listTop  int
	detail   viewport.Model
	status   string
}

// New builds the model. The host header is available before the first check.
func New(ctx context.Context, opts checks.Options) *Model {
	cctx, cancel := context.WithCancel(ctx)
	all := checks.All()
	rows := make([]checkRow, len(all))
	for i, c := range all {
		rows[i] = checkRow{check: c, counts: map[model.Severity]int{}}
	}
	sp := spinner.New(spinner.WithSpinner(spinner.MiniDot))
	bar := progress.New(progress.WithDefaultBlend(), progress.WithWidth(40))
	ti := textinput.New()
	ti.Prompt = "/ "
	ti.Placeholder = "Search titles and evidence. Enter to apply, Esc to cancel"
	vp := viewport.New()
	return &Model{
		ctx: cctx, cancel: cancel, opts: opts,
		events: make(chan checks.Event, 8), done: make(chan *model.Report, 1),
		st: newStyles(true), started: time.Now(), rows: rows,
		live: map[model.Severity]int{}, spinner: sp, progress: bar,
		search: ti, detail: vp, focus: paneList,
		host: checks.NewContext(cctx, opts).Host,
	}
}

// Init starts the scan on a background goroutine.
func (m *Model) Init() tea.Cmd {
	go func() {
		report := checks.Run(m.ctx, m.opts, func(ev checks.Event) {
			select {
			case m.events <- ev:
			case <-m.ctx.Done():
			}
		})
		m.done <- report
		close(m.events)
	}()
	return tea.Batch(m.waitEvent(), m.spinner.Tick, tea.RequestBackgroundColor, tick())
}

func tick() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m *Model) waitEvent() tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-m.events
		if !ok {
			return scanDoneMsg{report: <-m.done}
		}
		return scanEventMsg(ev)
	}
}

// Update handles a message.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.BackgroundColorMsg:
		m.st = newStyles(msg.IsDark())
		if m.phase == phaseResults {
			m.refreshDetail()
		}
		return m, nil
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.layout()
		return m, nil
	case tickMsg:
		if m.phase == phaseScan {
			m.elapsed = time.Since(m.started)
			return m, tick()
		}
		return m, nil
	case spinner.TickMsg:
		if m.phase != phaseScan {
			return m, nil
		}
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	case scanEventMsg:
		m.applyEvent(checks.Event(msg))
		return m, m.waitEvent()
	case scanDoneMsg:
		m.report = msg.report
		m.phase = phaseResults
		m.buildCategories()
		m.applyFilter()
		m.layout()
		return m, nil
	case tea.KeyPressMsg:
		return m.handleKey(msg)
	}
	if m.searchOn {
		var cmd tea.Cmd
		m.search, cmd = m.search.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m *Model) applyEvent(ev checks.Event) {
	if ev.Index >= len(m.rows) {
		return
	}
	row := &m.rows[ev.Index]
	if !ev.Done {
		row.status = rowRunning
		return
	}
	row.status = rowDone
	m.finished++
	for _, f := range ev.Findings {
		row.counts[f.Severity]++
		m.live[f.Severity]++
		if f.Severity <= model.High {
			m.alerts = append(m.alerts, f.Title)
		}
	}
}

func (m *Model) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	if key == "ctrl+c" {
		m.cancel()
		m.aborted = m.phase == phaseScan
		return m, tea.Quit
	}
	if m.phase == phaseScan {
		if key == "q" {
			m.cancel()
			m.aborted = true
			return m, tea.Quit
		}
		return m, nil
	}
	if m.searchOn {
		switch key {
		case "enter":
			m.query = strings.TrimSpace(m.search.Value())
			m.searchOn = false
			m.search.Blur()
			m.applyFilter()
			return m, nil
		case "esc":
			m.searchOn = false
			m.search.Blur()
			m.search.SetValue(m.query)
			return m, nil
		}
		var cmd tea.Cmd
		m.search, cmd = m.search.Update(msg)
		return m, cmd
	}
	switch key {
	case "q":
		m.cancel()
		return m, tea.Quit
	case "esc":
		if m.query != "" {
			m.query = ""
			m.search.SetValue("")
			m.applyFilter()
		} else if m.focus == paneDetail {
			m.focus = paneList
		}
		return m, nil
	case "/":
		m.searchOn = true
		m.search.SetValue(m.query)
		m.layout()
		return m, m.search.Focus()
	case "f":
		m.filter = (m.filter + 1) % filterCount
		m.applyFilter()
		return m, nil
	case "s":
		m.save()
		return m, nil
	case "tab":
		m.focus = (m.focus + 1) % 3
		return m, nil
	case "shift+tab":
		m.focus = (m.focus + 2) % 3
		return m, nil
	case "left", "h":
		if m.focus > paneCategories {
			m.focus--
		}
		return m, nil
	case "right", "l", "enter":
		if m.focus < paneDetail {
			m.focus++
		}
		return m, nil
	}
	switch m.focus {
	case paneCategories:
		switch key {
		case "up", "k":
			if m.catIdx > 0 {
				m.catIdx--
				m.applyFilter()
			}
		case "down", "j":
			if m.catIdx < len(m.cats) {
				m.catIdx++
				m.applyFilter()
			}
		}
	case paneList:
		m.moveCursor(key)
	case paneDetail:
		var cmd tea.Cmd
		m.detail, cmd = m.detail.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m *Model) moveCursor(key string) {
	n := len(m.visible)
	if n == 0 {
		return
	}
	page := m.listHeight()
	prev := m.cursor
	switch key {
	case "up", "k":
		m.cursor--
	case "down", "j":
		m.cursor++
	case "pgup", "ctrl+b":
		m.cursor -= page
	case "pgdown", "ctrl+f", "space":
		m.cursor += page
	case "home", "g":
		m.cursor = 0
	case "end", "G":
		m.cursor = n - 1
	default:
		return
	}
	m.cursor = max(0, min(m.cursor, n-1))
	if m.cursor != prev {
		m.ensureVisible()
		m.refreshDetail()
	}
}

func (m *Model) ensureVisible() {
	h := m.listHeight()
	if m.cursor < m.listTop {
		m.listTop = m.cursor
	} else if m.cursor >= m.listTop+h {
		m.listTop = m.cursor - h + 1
	}
	m.listTop = max(0, m.listTop)
}

func (m *Model) save() {
	if m.report == nil {
		return
	}
	path := output.DefaultFilename(m.report)
	if err := output.SaveJSON(path, m.report); err != nil {
		m.status = "Save failed: " + err.Error()
		return
	}
	m.status = "Saved " + path
}

func (m *Model) buildCategories() {
	seen := map[model.Category]bool{}
	for _, f := range m.report.Findings {
		seen[f.Category] = true
	}
	m.cats = nil
	for _, c := range model.Categories {
		if seen[c] {
			m.cats = append(m.cats, c)
		}
	}
}

func (m *Model) matches(f model.Finding) bool {
	if m.catIdx > 0 && f.Category != m.cats[m.catIdx-1] {
		return false
	}
	switch m.filter {
	case filterActionable:
		if f.Severity > model.Medium {
			return false
		}
	case filterUrgent:
		if f.Severity > model.High {
			return false
		}
	case filterSkipped:
		if f.Severity != model.Skipped {
			return false
		}
	}
	if m.query == "" {
		return true
	}
	q := strings.ToLower(m.query)
	if strings.Contains(strings.ToLower(f.Title), q) || strings.Contains(strings.ToLower(f.Detail), q) {
		return true
	}
	for _, e := range f.Evidence {
		if strings.Contains(strings.ToLower(e), q) {
			return true
		}
	}
	return false
}

func (m *Model) applyFilter() {
	m.visible = m.visible[:0]
	if m.report != nil {
		for i, f := range m.report.Findings {
			if m.matches(f) {
				m.visible = append(m.visible, i)
			}
		}
	}
	m.cursor, m.listTop = 0, 0
	m.refreshDetail()
}

func (m *Model) current() *model.Finding {
	if m.report == nil || m.cursor < 0 || m.cursor >= len(m.visible) {
		return nil
	}
	return &m.report.Findings[m.visible[m.cursor]]
}

// geometry describes the result layout for the current terminal size.
type geometry struct {
	wide                           bool
	catW, listW, detailW           int
	bodyH, listH, detailH, topRows int
}

func (m *Model) geometry() geometry {
	g := geometry{wide: m.width >= 110}
	header := 4
	footer := 2
	g.bodyH = max(m.height-header-footer, 6)
	const border = 2
	if g.wide {
		g.catW = 18
		rest := m.width - g.catW - border*3
		g.listW = rest * 45 / 100
		g.detailW = rest - g.listW
		g.listH = g.bodyH - border
		g.detailH = g.bodyH - border
		return g
	}
	g.topRows = 1
	inner := m.width - border
	g.listW, g.detailW = inner, inner
	avail := g.bodyH - g.topRows - border*2
	g.listH = max(avail*2/5, 3)
	g.detailH = max(avail-g.listH, 3)
	return g
}

func (m *Model) listHeight() int { return max(m.geometry().listH, 1) }

func (m *Model) layout() {
	if m.width == 0 {
		return
	}
	g := m.geometry()
	m.detail.SetWidth(g.detailW)
	m.detail.SetHeight(g.detailH)
	m.progress.SetWidth(min(max(m.width-30, 20), 70))
	m.search.SetWidth(max(m.width-6, 10))
	m.ensureVisible()
	m.refreshDetail()
}

func (m *Model) refreshDetail() {
	f := m.current()
	if f == nil {
		m.detail.SetContent(m.st.subtle.Render("No matching items."))
		m.detail.GotoTop()
		return
	}
	m.detail.SetContent(m.renderDetail(*f, max(m.geometry().detailW-1, 20)))
	m.detail.GotoTop()
}

func (m *Model) renderDetail(f model.Finding, width int) string {
	st := m.st
	wrap := lipgloss.NewStyle().Width(width)
	var b strings.Builder
	b.WriteString(st.badge(f.Severity, f.Severity.Label()))
	b.WriteString(" " + st.subtle.Render(f.Category.Label()) + "\n\n")
	b.WriteString(wrap.Inherit(st.bold).Render(f.Title) + "\n")
	if f.Detail != "" {
		b.WriteString("\n" + wrap.Inherit(st.text).Render(f.Detail) + "\n")
	}
	if f.Remediation != "" {
		b.WriteString("\n" + st.section.Render("Remediation") + "\n")
		b.WriteString(wrap.Inherit(st.accent).Render(f.Remediation) + "\n")
	}
	if len(f.Evidence) > 0 {
		b.WriteString("\n" + st.section.Render(fmt.Sprintf("Evidence (%d)", len(f.Evidence))) + "\n")
		inner := lipgloss.NewStyle().Width(max(width-2, 10)).Inherit(st.text)
		for _, e := range f.Evidence {
			lines := strings.Split(inner.Render(e), "\n")
			for i, l := range lines {
				prefix := "  "
				if i == 0 {
					prefix = st.faint.Render("• ")
				}
				b.WriteString(prefix + l + "\n")
			}
		}
	}
	if len(f.Refs) > 0 {
		b.WriteString("\n" + st.section.Render("References") + "\n")
		for _, r := range f.Refs {
			b.WriteString(wrap.Inherit(st.subtle).Render(r) + "\n")
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// View renders the screen.
func (m *Model) View() tea.View {
	content := ""
	switch {
	case m.width == 0:
	case m.width < minWidth || m.height < minHeight:
		content = fmt.Sprintf("Terminal too small (%dx%d), need at least %dx%d.", m.width, m.height, minWidth, minHeight)
	case m.phase == phaseScan:
		content = m.viewScan()
	default:
		content = m.viewResults()
	}
	v := tea.NewView(content)
	v.AltScreen = true
	v.WindowTitle = "ubuntu-sys-audit · " + m.host.Hostname
	return v
}

func (m *Model) viewHeaderLine() string {
	st := m.st
	title := gradientText("◆ ubuntu-sys-audit", st.p.accent, st.p.sev[model.Info])
	h := m.host
	info := fmt.Sprintf("%s  %s %s  kernel %s", h.Hostname, h.OSName, h.OSVersion, h.Kernel)
	return title + "  " + st.subtle.Render(ansi.Truncate(info, max(m.width-22, 10), "…"))
}

func (m *Model) viewScan() string {
	st := m.st
	var b strings.Builder
	b.WriteString(m.viewHeaderLine() + "\n")
	if !m.host.IsRoot {
		b.WriteString(st.warn.Render(ansi.Truncate("Not running as root, so some items will be marked not checked. Use sudo.", m.width, "…")) + "\n")
	}
	b.WriteString("\n")
	total := len(m.rows)
	pct := float64(m.finished) / float64(max(total, 1))
	b.WriteString(m.progress.ViewAs(pct))
	b.WriteString(st.subtle.Render(fmt.Sprintf("  %d/%d  %s", m.finished, total, m.elapsed.Round(time.Second))) + "\n\n")

	reserved := 8
	if !m.host.IsRoot {
		reserved++
	}
	avail := max(m.height-reserved, 3)
	twoCol := m.width >= 96 && total/2+total%2 <= avail
	if twoCol {
		half := total/2 + total%2
		colW := (m.width - 2) / 2
		var left, right []string
		for i := range half {
			left = append(left, m.renderRow(i, colW))
		}
		for i := half; i < total; i++ {
			right = append(right, m.renderRow(i, colW))
		}
		b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top,
			lipgloss.NewStyle().Width(colW+2).Render(strings.Join(left, "\n")),
			strings.Join(right, "\n")) + "\n")
	} else {
		start := 0
		for i, r := range m.rows {
			if r.status == rowRunning {
				start = i
			}
		}
		start = max(0, min(start-avail/2, total-avail))
		for i := start; i < min(start+avail, total); i++ {
			b.WriteString(m.renderRow(i, m.width-1) + "\n")
		}
	}
	status := m.renderLiveCounts()
	if n := len(m.alerts); n > 0 {
		status += "  " + st.sevStyle(model.Critical).Render("Latest: "+m.alerts[n-1])
	}
	b.WriteString("\n" + ansi.Truncate(status, m.width, "…"))
	b.WriteString("\n" + st.key.Render("q") + st.keyHelp.Render(" abort scan"))
	return b.String()
}

func (m *Model) renderLiveCounts() string {
	var parts []string
	for _, sev := range model.AllSeverities {
		n := m.live[sev]
		if n > 0 {
			parts = append(parts, m.st.sevStyle(sev).Render(fmt.Sprintf("%d %s", n, sev.Label())))
		}
	}
	if len(parts) == 0 {
		return m.st.faint.Render("No results yet")
	}
	return strings.Join(parts, m.st.faint.Render(" · "))
}

func (m *Model) renderRow(i, width int) string {
	st := m.st
	row := m.rows[i]
	var icon string
	switch row.status {
	case rowRunning:
		icon = m.spinner.View()
	case rowDone:
		worst := model.OK
		for _, sev := range []model.Severity{model.Medium, model.High, model.Critical} {
			if row.counts[sev] > 0 {
				worst = sev
			}
		}
		if worst == model.OK && row.counts[model.Skipped] > 0 {
			worst = model.Skipped
		}
		icon = st.sevStyle(worst).Render(severitySymbols[worst])
	default:
		icon = st.faint.Render("·")
	}
	nameStyle := st.faint
	switch row.status {
	case rowRunning:
		nameStyle = st.bold
	case rowDone:
		nameStyle = st.subtle
	}
	name := nameStyle.Render(ansi.Truncate(row.check.Name, max(width-14, 8), "…"))
	tail := ""
	for _, sev := range []model.Severity{model.Critical, model.High, model.Medium} {
		if n := row.counts[sev]; n > 0 {
			tail += " " + st.sevStyle(sev).Render(fmt.Sprintf("%d", n))
		}
	}
	return icon + " " + name + tail
}

func (m *Model) viewResults() string {
	st := m.st
	g := m.geometry()
	var b strings.Builder

	b.WriteString(m.viewHeaderLine() + "\n")
	if !m.host.IsRoot {
		b.WriteString(st.warn.Render(ansi.Truncate("Not running as root. Rescan with sudo to cover items marked not checked.", m.width, "…")) + "\n")
	} else {
		dur := time.Duration(m.report.DurationMS) * time.Millisecond
		note := fmt.Sprintf("Read-only scan finished in %s · A rootkit can falsify local results, so a clean result does not prove a clean host", dur.Round(100*time.Millisecond))
		b.WriteString(st.faint.Render(ansi.Truncate(note, m.width, "…")) + "\n")
	}
	var chips []string
	for _, sev := range model.AllSeverities {
		n := m.report.Summary.Count(sev)
		text := fmt.Sprintf("%d %s", n, sev.Label())
		if n > 0 {
			chips = append(chips, st.badge(sev, text))
		} else {
			chips = append(chips, st.faint.Padding(0, 1).Render(text))
		}
	}
	line := strings.Join(chips, " ")
	if m.filter != filterAll {
		line += "  " + st.accent.Render("Filter: "+filterLabels[m.filter])
	}
	if m.query != "" {
		line += "  " + st.accent.Render("Search: "+ansi.Truncate(m.query, 20, "…"))
	}
	b.WriteString(ansi.Truncate(line, m.width, "…") + "\n\n")

	if g.wide {
		cats := m.renderPane(paneCategories, m.renderCategories(g.catW, g.bodyH-2), g.catW, g.bodyH-2)
		list := m.renderPane(paneList, m.renderList(g.listW, g.listH), g.listW, g.listH)
		det := m.renderPane(paneDetail, m.detail.View(), g.detailW, g.detailH)
		b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, cats, list, det))
	} else {
		b.WriteString(m.renderCategoryTabs() + "\n")
		b.WriteString(m.renderPane(paneList, m.renderList(g.listW, g.listH), g.listW, g.listH) + "\n")
		b.WriteString(m.renderPane(paneDetail, m.detail.View(), g.detailW, g.detailH))
	}
	b.WriteString("\n" + m.renderFooter())
	return b.String()
}

func (m *Model) renderPane(p pane, content string, width, height int) string {
	style := m.st.pane
	if m.focus == p {
		style = m.st.paneFocus
	}
	return style.Width(width + 2).Height(height + 2).Render(content)
}

// categorySummary returns the number of findings to act on and the symbol
// severity for a category. A category with any unfinished check never shows as
// passed, even when everything else in it is clean.
func (m *Model) categorySummary(c model.Category) (total int, symbol model.Severity) {
	symbol = model.OK
	skipped := false
	for _, f := range m.report.Findings {
		if c != "" && f.Category != c {
			continue
		}
		switch {
		case f.Severity <= model.Medium:
			total++
			if symbol > f.Severity {
				symbol = f.Severity
			}
		case f.Severity == model.Skipped:
			skipped = true
		}
	}
	if symbol == model.OK && skipped {
		symbol = model.Skipped
	}
	return total, symbol
}

func (m *Model) renderCategories(width, height int) string {
	st := m.st
	var lines []string
	row := func(idx int, label string, c model.Category) {
		n, symbol := m.categorySummary(c)
		count := ""
		if n > 0 {
			count = fmt.Sprintf("%d", n)
		}
		labelW := width - 3 - lipgloss.Width(count)
		padded := label + strings.Repeat(" ", max(labelW-lipgloss.Width(label), 0))
		dot := st.sevStyle(symbol).Render(severitySymbols[symbol])
		if idx == m.catIdx {
			if m.focus == paneCategories {
				lines = append(lines, dot+" "+st.selected.Render(padded+count+" "))
			} else {
				lines = append(lines, dot+" "+st.selectedDim.Render(padded+count+" "))
			}
			return
		}
		lines = append(lines, dot+" "+st.text.Render(padded)+st.sevStyle(symbol).Render(count))
	}
	row(0, "All", "")
	for i, c := range m.cats {
		row(i+1, c.Label(), c)
	}
	if len(lines) > height {
		lines = lines[:height]
	}
	return strings.Join(lines, "\n")
}

func (m *Model) renderCategoryTabs() string {
	st := m.st
	labels := []string{"All"}
	for _, c := range m.cats {
		labels = append(labels, c.Label())
	}
	var parts []string
	for i, l := range labels {
		if i == m.catIdx {
			parts = append(parts, st.selected.Render(" "+l+" "))
		} else {
			parts = append(parts, st.subtle.Render(" "+l+" "))
		}
	}
	// The tabs may not all fit on a narrow terminal, so scroll to keep the
	// selected one on screen. One cell is reserved for the leading marker.
	start := 0
	for start < m.catIdx && lipgloss.Width(strings.Join(parts[start:m.catIdx+1], "")) > m.width-1 {
		start++
	}
	line := strings.Join(parts[start:], "")
	if start > 0 {
		line = st.faint.Render("…") + line
	}
	return ansi.Truncate(line, m.width, "…")
}

func (m *Model) renderList(width, height int) string {
	st := m.st
	if len(m.visible) == 0 {
		return st.subtle.Render("No matching items.")
	}
	var lines []string
	end := min(m.listTop+height, len(m.visible))
	for i := m.listTop; i < end; i++ {
		f := m.report.Findings[m.visible[i]]
		symbol := severitySymbols[f.Severity]
		title := ansi.Truncate(f.Title, max(width-3, 4), "…")
		if i == m.cursor {
			pad := max(width-2-lipgloss.Width(title), 0)
			body := title + strings.Repeat(" ", pad)
			style := st.selectedDim
			if m.focus == paneList {
				style = st.selected
			}
			lines = append(lines, st.sevStyle(f.Severity).Render(symbol)+" "+style.Render(body))
			continue
		}
		titleStyle := st.text
		if f.Severity >= model.OK {
			titleStyle = st.subtle
		}
		lines = append(lines, st.sevStyle(f.Severity).Render(symbol)+" "+titleStyle.Render(title))
	}
	return strings.Join(lines, "\n")
}

func (m *Model) renderFooter() string {
	st := m.st
	if m.searchOn {
		return m.search.View()
	}
	hint := func(k, h string) string { return st.key.Render(k) + st.keyHelp.Render(" "+h) }
	keys := []string{hint("↑↓", "move"), hint("tab", "switch pane"), hint("f", "filter"), hint("/", "search"), hint("s", "save JSON"), hint("q", "quit")}
	if m.focus == paneDetail {
		keys[0] = hint("↑↓", "scroll")
	}
	left := fmt.Sprintf("%d/%d", min(m.cursor+1, len(m.visible)), len(m.visible))
	line := st.faint.Render(left) + "  " + strings.Join(keys, st.faint.Render("  "))
	if m.status != "" {
		line += "  " + st.accent.Render(m.status)
	}
	return ansi.Truncate(line, m.width, "…")
}

// Run runs the TUI and returns the finished report, or nil when the scan was
// aborted before it completed.
func Run(ctx context.Context, opts checks.Options) (*model.Report, error) {
	m := New(ctx, opts)
	defer m.cancel()
	final, err := tea.NewProgram(m, tea.WithContext(ctx)).Run()
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, tea.ErrInterrupted) || errors.Is(err, tea.ErrProgramKilled) {
			return nil, nil
		}
		return nil, err
	}
	fm, ok := final.(*Model)
	if !ok || fm.aborted {
		return nil, nil
	}
	return fm.report, nil
}
