package tui

import (
	"mitre-explorer/internal/attack"

	tea "charm.land/bubbletea/v2"
)

type screen uint8

const (
	screenTactics screen = iota
	screenTechniques
	screenTechniqueDetail
)

type cacheLoadedMsg struct {
	cache attack.CacheData
}

type cacheLoadFailedMsg struct {
	err error
}

type model struct {
	options         Options
	cache           attack.CacheData
	tactics         []string
	techniques      []attack.Technique
	screen          screen
	tacticCursor    int
	techniqueCursor int
	width           int
	height          int
	loading         bool
	loadErr         error
}

func newModel(options Options) model {
	return model{
		options: options,
		screen:  screenTactics,
		loading: true,
	}
}

func (m model) Init() tea.Cmd {
	return loadCache(m.options.CachePath)
}

func loadCache(path string) tea.Cmd {
	return func() tea.Msg {
		cache, err := attack.LoadCacheData(path)
		if err != nil {
			return cacheLoadFailedMsg{err: err}
		}
		return cacheLoadedMsg{cache: cache}
	}
}

func (m model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case tea.WindowSizeMsg:
		m.width = message.Width
		m.height = message.Height
	case cacheLoadedMsg:
		m.cache = message.cache
		m.tactics = attack.CollectUniqueTactics(m.cache.Techniques, m.options.TacticOrder)
		m.loading = false
		m.loadErr = nil
	case cacheLoadFailedMsg:
		m.loading = false
		m.loadErr = message.err
	case tea.KeyPressMsg:
		return m.handleKey(message.String())
	}

	return m, nil
}

func (m model) handleKey(key string) (tea.Model, tea.Cmd) {
	if key == "q" || key == "ctrl+c" {
		return m, tea.Quit
	}
	if key == "esc" {
		if m.screen == screenTactics || m.loading || m.loadErr != nil {
			return m, tea.Quit
		}
		m.goBack()
		return m, nil
	}
	if m.loading || m.loadErr != nil {
		return m, nil
	}

	switch key {
	case "up", "k":
		m.moveCursor(-1)
	case "down", "j":
		m.moveCursor(1)
	case "enter":
		m.selectCurrent()
	case "b":
		m.goBack()
	}

	return m, nil
}

func (m *model) moveCursor(delta int) {
	var cursor *int
	var length int

	switch m.screen {
	case screenTactics:
		cursor, length = &m.tacticCursor, len(m.tactics)
	case screenTechniques:
		cursor, length = &m.techniqueCursor, len(m.techniques)
	default:
		return
	}

	if length == 0 {
		return
	}
	*cursor = min(max(*cursor+delta, 0), length-1)
}

func (m *model) selectCurrent() {
	switch m.screen {
	case screenTactics:
		if len(m.tactics) == 0 {
			return
		}
		m.techniques = attack.ListByTactic(m.cache.Techniques, m.tactics[m.tacticCursor])
		m.techniqueCursor = 0
		m.screen = screenTechniques
	case screenTechniques:
		if len(m.techniques) > 0 {
			m.screen = screenTechniqueDetail
		}
	}
}

func (m *model) goBack() {
	switch m.screen {
	case screenTechniqueDetail:
		m.screen = screenTechniques
	case screenTechniques:
		m.screen = screenTactics
	}
}

func (m model) selectedTactic() (string, bool) {
	if m.tacticCursor < 0 || m.tacticCursor >= len(m.tactics) {
		return "", false
	}
	return m.tactics[m.tacticCursor], true
}

func (m model) selectedTechnique() (attack.Technique, bool) {
	if m.techniqueCursor < 0 || m.techniqueCursor >= len(m.techniques) {
		return attack.Technique{}, false
	}
	return m.techniques[m.techniqueCursor], true
}
