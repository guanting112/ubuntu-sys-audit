package tui

import (
	"fmt"
	"image/color"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"ubuntu-sys-audit/internal/model"
)

// The opening screen stays up this long. The scan is already running behind it,
// so it costs no time, and any key dismisses it.
const (
	splashDuration = 1500 * time.Millisecond
	animFrame      = 180 * time.Millisecond
)

type (
	splashDoneMsg struct{}
	animTickMsg   struct{}
)

func splashTimer() tea.Cmd {
	return tea.Tick(splashDuration, func(time.Time) tea.Msg { return splashDoneMsg{} })
}

func animTick() tea.Cmd {
	return tea.Tick(animFrame, func(time.Time) tea.Msg { return animTickMsg{} })
}

// All art is plain ASCII. Unicode box and block characters render at different
// widths depending on the terminal and locale, which would break the alignment.
//
// {e} is the eyes and {l} the lens of the magnifying glass.
const detective = `       ______
     _|______|_
       ({e})
       (  ^  )
        \ - /
   .-----'-'-----.
  /  /|       |\  \       .---.
 /  / |  [=]  | \  \_____/  {l}  \
(__/  |       |  \______ \     /
      |___|___|          '---'
      |   |   |
      |   |   |
     _|   |   |_
    (___|   |___)`

const titleSys = ` ___  __   __  ___
/ __| \ \ / / / __|
\__ \  \ V /  \__ \
|___/   |_|   |___/`

const titleAudit = `   _    _   _  ___   ___  _____
  /_\  | | | ||   \ |_ _||_   _|
 / _ \ | |_| || |) | | |   | |
/_/ \_\ \___/ |___/ |___|  |_|`

// Every eye string is the same width, so the face does not jump between frames.
var (
	eyesCalm    = []string{"o   o", "o   o", "o   o", "-   -", "o   o", " o o ", "o o  ", " o o "}
	eyesAlarmed = []string{"O   O", "O   O", "O   O", "-   -"}
	lensCalm    = []string{"O", "o", ".", "o"}
	lensAlarmed = []string{"!", "!", "?", "!"}
)

// detectiveFrame returns the art for one animation frame. An alarmed detective
// has found something serious.
func detectiveFrame(frame int, alarmed bool) []string {
	eyes, lens := eyesCalm, lensCalm
	if alarmed {
		eyes, lens = eyesAlarmed, lensAlarmed
	}
	art := strings.ReplaceAll(detective, "{e}", eyes[frame%len(eyes)])
	art = strings.ReplaceAll(art, "{l}", lens[frame%len(lens)])
	return padded(strings.Split(art, "\n"))
}

// miniDetective is the small version for terminals with no room for the art.
func miniDetective(frame int, alarmed bool) string {
	if alarmed {
		return []string{"(O_O)-!", "(O_O)-!", "(O_O)-?", "(-_-)-!"}[frame%4]
	}
	return []string{"(o_o)-O", "(o_o)-o", "(o_o)-.", "(-_-)-o"}[frame%4]
}

// padded gives every line the same width, so joined blocks stay rectangular.
func padded(lines []string) []string {
	width := 0
	for _, l := range lines {
		width = max(width, len(l))
	}
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = l + strings.Repeat(" ", width-len(l))
	}
	return out
}

// verticalGradient colours each line along a gradient from top to bottom.
func (m *Model) verticalGradient(lines []string, to color.Color) string {
	colors := lipgloss.Blend1D(max(len(lines), 2), m.st.p.accent, to)
	var b strings.Builder
	for i, l := range lines {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(colors[i]).Render(l))
	}
	return b.String()
}

// alarmed reports whether the scan has found anything critical or high so far.
func (m *Model) alarmed() bool {
	return m.live[model.Critical]+m.live[model.High] > 0
}

func (m *Model) detectiveArt() string {
	to := m.st.p.sev[model.Info]
	if m.alarmed() {
		to = m.st.p.sev[model.Critical]
	}
	return m.verticalGradient(detectiveFrame(m.frame, m.alarmed()), to)
}

func (m *Model) viewSplash() string {
	st := m.st
	info := st.p.sev[model.Info]
	person := m.detectiveArt()
	tagline := st.subtle.Render("Read-only security audit for Ubuntu")
	if v := m.opts.Version; v != "" {
		tagline += st.faint.Render("  " + v)
	}
	title := m.verticalGradient(padded(strings.Split(titleSys+"\n\n"+titleAudit, "\n")), info)

	art := lipgloss.JoinHorizontal(lipgloss.Center, person, "   ", lipgloss.JoinVertical(lipgloss.Left, title, "", tagline))
	if lipgloss.Width(art) > m.width {
		// Too narrow for the large title.
		art = lipgloss.JoinVertical(lipgloss.Center, person, gradientText("ubuntu-sys-audit", st.p.accent, info), tagline)
	}
	hint := st.faint.Render("Scanning in the background. Press any key to continue.")
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, lipgloss.JoinVertical(lipgloss.Center, art, "", hint))
}

const (
	scanArtGap = 3
	// Below this, the check list beside the art would be too narrow to read.
	scanMinList = 40
	// Two columns of checks need this much room to show most names in full.
	scanTwoColumns = 84
)

// scanArtFits reports whether the art has room beside the check list.
func (m *Model) scanArtFits(avail int) bool {
	lines := detectiveFrame(0, false)
	return m.width >= len(lines[0])+scanArtGap+scanMinList && avail >= len(lines)
}

// scanBody renders the check list, with the detective beside it when there is room.
func (m *Model) scanBody(avail int) string {
	if !m.scanArtFits(avail) {
		return m.renderChecks(m.width, avail)
	}
	art := m.detectiveArt()
	list := m.renderChecks(m.width-lipgloss.Width(art)-scanArtGap, avail)
	return lipgloss.JoinHorizontal(lipgloss.Top, art, strings.Repeat(" ", scanArtGap), list)
}

func (m *Model) renderChecks(width, avail int) string {
	total := len(m.rows)
	half := total/2 + total%2
	if width >= scanTwoColumns && half <= avail {
		colW := (width - 2) / 2
		var left, right []string
		for i := range half {
			left = append(left, m.renderRow(i, colW))
		}
		for i := half; i < total; i++ {
			right = append(right, m.renderRow(i, colW))
		}
		return lipgloss.JoinHorizontal(lipgloss.Top,
			lipgloss.NewStyle().Width(colW+2).Render(strings.Join(left, "\n")),
			strings.Join(right, "\n"))
	}
	// One column, kept in a window around the running check.
	start := 0
	for i, r := range m.rows {
		if r.status == rowRunning {
			start = i
		}
	}
	start = max(0, min(start-avail/2, total-avail))
	var lines []string
	for i := start; i < min(start+avail, total); i++ {
		lines = append(lines, m.renderRow(i, width-1))
	}
	return strings.Join(lines, "\n")
}

// progressSuffix follows the progress bar, with the small detective when the
// large one has no room.
func (m *Model) progressSuffix(total, avail int) string {
	s := m.st.subtle.Render(fmt.Sprintf("  %d/%d  %s", m.finished, total, m.elapsed.Round(time.Second)))
	if m.scanArtFits(avail) {
		return s
	}
	style := m.st.accent
	if m.alarmed() {
		style = m.st.sevStyle(model.Critical)
	}
	return s + "  " + style.Render(miniDetective(m.frame, m.alarmed()))
}
