package tui

import tea "charm.land/bubbletea/v2"

func (m model) updateHelp(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "?", "esc", "b":
		m.helpVisible = false
	case "up", "k":
		m.helpOffset = max(0, m.helpOffset-1)
	case "down", "j":
		m.helpOffset = min(m.helpMaxOffset(), m.helpOffset+1)
	}
	return m, nil
}
