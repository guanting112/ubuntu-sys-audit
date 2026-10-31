package tui

import (
	"image/color"
	"strings"

	"charm.land/lipgloss/v2"

	"ubuntu-sys-audit/internal/model"
)

type palette struct {
	text, subtle, faint, border, accent, selectBG color.Color
	sev                                           map[model.Severity]color.Color
	badgeFG                                       color.Color
}

func newPalette(dark bool) palette {
	pick := lipgloss.LightDark(dark)
	return palette{
		text:     pick(lipgloss.Color("#1C1C24"), lipgloss.Color("#E6E6EF")),
		subtle:   pick(lipgloss.Color("#5C5C70"), lipgloss.Color("#9A9AB0")),
		faint:    pick(lipgloss.Color("#8E8EA0"), lipgloss.Color("#62627A")),
		border:   pick(lipgloss.Color("#C4C4D4"), lipgloss.Color("#3A3A4E")),
		accent:   pick(lipgloss.Color("#5B3FD6"), lipgloss.Color("#A78BFA")),
		selectBG: pick(lipgloss.Color("#E4DEFB"), lipgloss.Color("#2E2850")),
		badgeFG:  lipgloss.Color("#101018"),
		sev: map[model.Severity]color.Color{
			model.Critical: pick(lipgloss.Color("#D1124F"), lipgloss.Color("#FF5C8A")),
			model.High:     pick(lipgloss.Color("#C75300"), lipgloss.Color("#FF9440")),
			model.Medium:   pick(lipgloss.Color("#8A6D00"), lipgloss.Color("#F5D040")),
			model.Info:     pick(lipgloss.Color("#0A6EBD"), lipgloss.Color("#5CB8FF")),
			model.OK:       pick(lipgloss.Color("#0B7A43"), lipgloss.Color("#4ADE80")),
			model.Skipped:  pick(lipgloss.Color("#6B6B80"), lipgloss.Color("#8C8CA3")),
		},
	}
}

type styles struct {
	p palette

	title, subtle, faint, text, bold, accent lipgloss.Style
	section                                  lipgloss.Style
	pane, paneFocus                          lipgloss.Style
	selected, selectedDim                    lipgloss.Style
	key, keyHelp                             lipgloss.Style
	warn                                     lipgloss.Style
}

func newStyles(dark bool) styles {
	p := newPalette(dark)
	base := lipgloss.NewStyle().Foreground(p.text)
	return styles{
		p:           p,
		title:       lipgloss.NewStyle().Bold(true).Foreground(p.accent),
		subtle:      lipgloss.NewStyle().Foreground(p.subtle),
		faint:       lipgloss.NewStyle().Foreground(p.faint),
		text:        base,
		bold:        base.Bold(true),
		accent:      lipgloss.NewStyle().Foreground(p.accent),
		section:     lipgloss.NewStyle().Bold(true).Foreground(p.subtle),
		pane:        lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(p.border),
		paneFocus:   lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(p.accent),
		selected:    lipgloss.NewStyle().Background(p.selectBG).Foreground(p.text).Bold(true),
		selectedDim: lipgloss.NewStyle().Background(p.selectBG).Foreground(p.subtle),
		key:         lipgloss.NewStyle().Foreground(p.accent).Bold(true),
		keyHelp:     lipgloss.NewStyle().Foreground(p.subtle),
		warn:        lipgloss.NewStyle().Foreground(p.sev[model.High]).Bold(true),
	}
}

func (s styles) sevStyle(sev model.Severity) lipgloss.Style {
	return lipgloss.NewStyle().Foreground(s.p.sev[sev])
}

func (s styles) badge(sev model.Severity, text string) string {
	return lipgloss.NewStyle().
		Background(s.p.sev[sev]).
		Foreground(s.p.badgeFG).
		Bold(true).
		Padding(0, 1).
		Render(text)
}

var severitySymbols = map[model.Severity]string{
	model.Critical: "●", model.High: "●", model.Medium: "●",
	model.Info: "○", model.OK: "✓", model.Skipped: "–",
}

// gradientText colours each rune along a two stop gradient.
func gradientText(s string, from, to color.Color) string {
	runes := []rune(s)
	if len(runes) == 0 {
		return ""
	}
	steps := len(runes)
	if steps < 2 {
		steps = 2
	}
	colors := lipgloss.Blend1D(steps, from, to)
	var b strings.Builder
	for i, r := range runes {
		b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(colors[i]).Render(string(r)))
	}
	return b.String()
}
