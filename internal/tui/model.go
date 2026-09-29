package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

const wideBanner = ` __  __ ___ _____ ____  _____    _____  __  __ ____  _      ___  ____  _____ ____
|  \/  |_ _|_   _|  _ \| ____|  | ____| \ \/ /|  _ \| |    / _ \|  _ \| ____|  _ \
| |\/| || |  | | | |_) |  _|    |  _|    \  / | |_) | |   | | | | |_) |  _| | |_) |
| |  | || |  | | |  _ <| |___   | |___   /  \ |  __/| |___| |_| |  _ <| |___|  _ <
|_|  |_|___| |_| |_| \_\_____|  |_____| /_/\_\|_|   |_____|\___/|_| \_\_____|_| \_\`

const compactBanner = "MITRE EXPLORER"

type model struct {
	options Options
	width   int
	height  int
}

func newModel(options Options) model {
	return model{options: options}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case tea.WindowSizeMsg:
		m.width = message.Width
		m.height = message.Height
	case tea.KeyPressMsg:
		switch message.String() {
		case "q", "esc", "ctrl+c":
			return m, tea.Quit
		}
	}

	return m, nil
}

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
	return m.renderCompact(width)
}

func (m model) renderWide(width, height int) string {
	leftWidth := 22
	rightWidth := width - leftWidth - 4
	bodyHeight := max(7, height-13)

	left := m.panelStyle(leftWidth, bodyHeight).Render(strings.Join([]string{
		m.headingStyle().Render("NAVIGATE"),
		"",
		"> Overview",
		"  Tactics",
		"  Techniques",
		"  Search",
	}, "\n"))
	right := m.panelStyle(rightWidth, bodyHeight).Render(strings.Join([]string{
		m.headingStyle().Render("TUI FOUNDATION"),
		"",
		"The full-screen interface is ready.",
		"",
		"The next section will connect this layout to",
		"the selected matrix, tactics, and techniques.",
	}, "\n"))

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

func (m model) renderCompact(width int) string {
	contentWidth := max(30, width-2)
	return strings.Join([]string{
		m.titleStyle().Render(compactBanner),
		m.statusLine(),
		"",
		m.panelStyle(contentWidth-2, 7).Render(strings.Join([]string{
			m.headingStyle().Render("TUI FOUNDATION"),
			"",
			"Responsive compact layout active.",
			"Matrix navigation arrives next.",
		}, "\n")),
		"",
		m.footer(),
	}, "\n")
}

func (m model) renderSmall(width, height int) string {
	return fmt.Sprintf("%s\nTerminal too small (%dx%d). Resize to at least 36x10.\n%s",
		compactBanner, width, height, m.footer())
}

func (m model) statusLine() string {
	return fmt.Sprintf("Matrix: %s  Cache: %s  Version: %s",
		m.options.Matrix, m.options.CachePath, m.options.Version)
}

func (m model) footer() string {
	return m.mutedStyle().Render("q / Esc / Ctrl+C  quit")
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
		Height(height)
	if !m.options.Plain {
		style = style.BorderForeground(lipgloss.Color("#3B8793"))
	}
	return style
}
