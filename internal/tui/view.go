package tui

import (
	"fmt"
	"strings"

	"mitre-explorer/internal/attack"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

const wideBanner = ` __  __ ___ _____ ____  _____    _____  __  __ ____  _      ___  ____  _____ ____
|  \/  |_ _|_   _|  _ \| ____|  | ____| \ \/ /|  _ \| |    / _ \|  _ \| ____|  _ \
| |\/| || |  | | | |_) |  _|    |  _|    \  / | |_) | |   | | | | |_) |  _| | |_) |
| |  | || |  | | |  _ <| |___   | |___   /  \ |  __/| |___| |_| |  _ <| |___|  _ <
|_|  |_|___| |_| |_| \_\_____|  |_____| /_/\_\|_|   |_____|\___/|_| \_\_____|_| \_\`

const compactBanner = "MITRE EXPLORER"

func (m model) View() tea.View {
	view := tea.NewView(m.render())
	view.AltScreen = true
	view.WindowTitle = "MITRE Explorer"
	return view
}

func (m model) render() string {
	width, height := m.width, m.height
	if width == 0 {
		width = 100
	}
	if height == 0 {
		height = 30
	}

	if width < 36 || height < 10 {
		return m.renderSmall(width, height)
	}
	if width >= 76 && height >= 18 {
		return m.renderWide(width, height)
	}
	return m.renderCompact(width, height)
}

func (m model) renderWide(width, height int) string {
	leftWidth := 34
	rightWidth := width - leftWidth - 4
	bodyHeight := max(7, height-13)

	left := m.panelStyle(leftWidth, bodyHeight).Render(m.leftPanel(bodyHeight-2, leftWidth-4))
	right := m.panelStyle(rightWidth, bodyHeight).Render(m.rightPanel(rightWidth-4, bodyHeight-2))
	header := compactBanner
	if width >= 100 && height >= 24 {
		header = wideBanner
	}

	return strings.Join([]string{
		m.titleStyle().Render(header),
		m.statusLine(),
		"",
		lipgloss.JoinHorizontal(lipgloss.Top, left, right),
		"",
		m.footer(),
	}, "\n")
}

func (m model) renderCompact(width, height int) string {
	panelWidth := max(30, width-4)
	panelHeight := max(5, height-7)
	return strings.Join([]string{
		m.titleStyle().Render(compactBanner),
		truncateText(m.statusLine(), width),
		"",
		m.panelStyle(panelWidth, panelHeight).Render(m.singlePanel(panelWidth-4, panelHeight-2)),
		"",
		m.footer(),
	}, "\n")
}

func (m model) renderSmall(width, height int) string {
	return fmt.Sprintf("%s\nTerminal too small (%dx%d). Resize to at least 36x10.\n%s",
		compactBanner, width, height, m.footer())
}

func (m model) leftPanel(maxRows, width int) string {
	if m.loading {
		return m.headingStyle().Render("LOADING CACHE")
	}
	if m.loadErr != nil {
		return m.headingStyle().Render("CACHE UNAVAILABLE")
	}

	switch m.screen {
	case screenTactics:
		return m.listContent("TACTICS", m.tactics, m.tacticCursor, maxRows, width)
	case screenTechniques, screenTechniqueDetail:
		labels := make([]string, 0, len(m.techniques))
		for _, technique := range m.techniques {
			labels = append(labels, technique.ID+"  "+technique.Name)
		}
		return m.listContent("TECHNIQUES", labels, m.techniqueCursor, maxRows, width)
	default:
		return ""
	}
}

func (m model) rightPanel(width, height int) string {
	var content string
	if m.loading {
		content = strings.Join([]string{
			m.headingStyle().Render("LOADING CACHE"),
			"",
			"Reading the selected matrix cache...",
		}, "\n")
	} else if m.loadErr != nil {
		content = strings.Join([]string{
			m.headingStyle().Render("CACHE UNAVAILABLE"),
			"",
			m.loadErr.Error(),
			"",
			fmt.Sprintf("Run: go run . update --matrix %s", m.options.Matrix),
		}, "\n")
	} else {
		content = m.contextContent()
	}

	return lipgloss.NewStyle().Width(width).MaxWidth(width).MaxHeight(height).Render(content)
}

func (m model) singlePanel(width, height int) string {
	if m.loading || m.loadErr != nil || m.screen == screenTechniqueDetail {
		return m.rightPanel(width, height)
	}
	return m.leftPanel(height, width)
}

func (m model) contextContent() string {
	switch m.screen {
	case screenTactics:
		tactic, ok := m.selectedTactic()
		if !ok {
			return m.headingStyle().Render("NO TACTICS") + "\n\nThe cache contains no tactic-linked techniques."
		}
		count := len(attack.ListByTactic(m.cache.Techniques, tactic))
		return strings.Join([]string{
			m.headingStyle().Render(tactic),
			"",
			fmt.Sprintf("%d technique(s)", count),
			"",
			"Press Enter to browse this tactic.",
		}, "\n")
	case screenTechniques:
		technique, ok := m.selectedTechnique()
		if !ok {
			return m.headingStyle().Render("NO TECHNIQUES") + "\n\nThis tactic has no techniques."
		}
		return strings.Join([]string{
			m.headingStyle().Render(technique.Name),
			"",
			"ID: " + technique.ID,
			"Platforms: " + joinedOrUnavailable(technique.Platforms),
			"",
			"Press Enter for full details.",
		}, "\n")
	case screenTechniqueDetail:
		technique, ok := m.selectedTechnique()
		if !ok {
			return m.headingStyle().Render("TECHNIQUE UNAVAILABLE")
		}
		return m.techniqueDetails(technique)
	default:
		return ""
	}
}

func (m model) techniqueDetails(technique attack.Technique) string {
	description := strings.TrimSpace(technique.Description)
	if description == "" {
		description = "Not available"
	}
	return strings.Join([]string{
		m.headingStyle().Render("TECHNIQUE DETAILS"),
		"",
		technique.ID + "  " + technique.Name,
		"Tactics: " + joinedOrUnavailable(technique.Tactics),
		"Platforms: " + joinedOrUnavailable(technique.Platforms),
		"Data sources: " + joinedOrUnavailable(technique.DataSources),
		"",
		"Description:",
		description,
	}, "\n")
}

func (m model) listContent(title string, items []string, cursor, maxRows, width int) string {
	lines := []string{m.headingStyle().Render(title), ""}
	if len(items) == 0 {
		return strings.Join(append(lines, "No items found."), "\n")
	}

	available := max(1, maxRows-len(lines))
	start, end := visibleRange(len(items), cursor, available)
	for index := start; index < end; index++ {
		prefix := "  "
		if index == cursor {
			prefix = "> "
		}
		line := fmt.Sprintf("%s%2d  %s", prefix, index+1, items[index])
		line = truncateText(line, width)
		if index == cursor {
			line = m.selectedStyle().Render(line)
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func visibleRange(length, cursor, size int) (int, int) {
	if length <= size {
		return 0, length
	}
	start := cursor - size/2
	start = min(max(start, 0), length-size)
	return start, start + size
}

func truncateText(value string, width int) string {
	if width <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= width {
		return value
	}
	if width <= 3 {
		return string(runes[:width])
	}
	return string(runes[:width-3]) + "..."
}

func joinedOrUnavailable(values []string) string {
	if len(values) == 0 {
		return "Not available"
	}
	return strings.Join(values, ", ")
}

func (m model) statusLine() string {
	return fmt.Sprintf("Matrix: %s  Cache: %s  Version: %s",
		m.options.Matrix, m.options.CachePath, m.options.Version)
}

func (m model) footer() string {
	var text string
	switch {
	case m.loading || m.loadErr != nil:
		text = "q / Esc / Ctrl+C  quit"
	case m.screen == screenTactics:
		text = "up/k down/j  move    Enter  select    q/Esc  quit"
	default:
		text = "up/k down/j  move    Enter  select    b/Esc  back    q  quit"
	}
	return m.mutedStyle().Render(text)
}

func (m model) titleStyle() lipgloss.Style {
	style := lipgloss.NewStyle()
	if !m.options.Plain {
		style = style.Bold(true).Foreground(lipgloss.Color("#58C7D9"))
	}
	return style
}

func (m model) headingStyle() lipgloss.Style {
	style := lipgloss.NewStyle()
	if !m.options.Plain {
		style = style.Bold(true).Foreground(lipgloss.Color("#E8B04A"))
	}
	return style
}

func (m model) selectedStyle() lipgloss.Style {
	style := lipgloss.NewStyle()
	if !m.options.Plain {
		style = style.Bold(true).Foreground(lipgloss.Color("#58C7D9"))
	}
	return style
}

func (m model) mutedStyle() lipgloss.Style {
	style := lipgloss.NewStyle()
	if !m.options.Plain {
		style = style.Foreground(lipgloss.Color("#80878F"))
	}
	return style
}

func (m model) panelStyle(width, height int) lipgloss.Style {
	style := lipgloss.NewStyle().
		Border(lipgloss.ASCIIBorder()).
		Padding(0, 1).
		Width(width).
		Height(height).
		MaxWidth(width).
		MaxHeight(height)
	if !m.options.Plain {
		style = style.BorderForeground(lipgloss.Color("#3B8793"))
	}
	return style
}
