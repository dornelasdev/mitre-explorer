package tui

import (
	"strings"

	"mitre-explorer/internal/attack"

	tea "charm.land/bubbletea/v2"
)

type pageKind uint8

const (
	pageList pageKind = iota
	pageDetail
)

type page struct {
	kind      pageKind
	title     string
	items     []browseItem
	cursor    int
	offset    int
	detail    browseItem
	relations []browseItem
}

type cacheLoadedMsg struct {
	matrix MatrixOption
	cache  attack.CacheData
}

type cacheLoadFailedMsg struct {
	matrix MatrixOption
	err    error
}

type model struct {
	options       Options
	cache         attack.CacheData
	tactics       []string
	pages         []page
	search        searchState
	matrixPicker  matrixPickerState
	helpVisible   bool
	helpOffset    int
	failedMatrix  *MatrixOption
	loadingMatrix *MatrixOption
	width         int
	height        int
	loading       bool
	loadErr       error
}

func newModel(options Options) model {
	return model{options: options, search: newSearchState(options.Plain), loading: true}
}

func (m model) Init() tea.Cmd {
	return loadCache(m.currentMatrix())
}

func loadCache(matrix MatrixOption) tea.Cmd {
	return func() tea.Msg {
		cache, err := attack.LoadCacheData(matrix.CachePath)
		if err != nil {
			return cacheLoadFailedMsg{matrix: matrix, err: err}
		}
		return cacheLoadedMsg{matrix: matrix, cache: cache}
	}
}

func (m model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case tea.WindowSizeMsg:
		m.width = message.Width
		m.height = message.Height
		m.setSearchWidth()
	case cacheLoadedMsg:
		matrix := message.matrix
		if matrix.Name == "" {
			matrix = m.currentMatrix()
		}
		m.activateMatrix(matrix, message.cache)
	case cacheLoadFailedMsg:
		m.loading = false
		m.loadingMatrix = nil
		m.loadErr = message.err
		failed := message.matrix
		if failed.Name == "" {
			failed = m.currentMatrix()
		}
		m.failedMatrix = &failed
	case tea.KeyPressMsg:
		if m.search.active {
			return m.updateSearch(message)
		}
		if m.matrixPicker.active {
			return m.updateMatrixPicker(message.String())
		}
		if m.helpVisible {
			return m.updateHelp(message.String())
		}
		return m.handleKey(message.String())
	}
	if m.search.active {
		var command tea.Cmd
		m.search.input, command = m.search.input.Update(message)
		return m, command
	}

	return m, nil
}

func (m model) handleKey(key string) (tea.Model, tea.Cmd) {
	if key == "q" || key == "ctrl+c" {
		return m, tea.Quit
	}
	if key == "?" {
		m.helpVisible = true
		m.helpOffset = 0
		return m, nil
	}
	if key == "m" && !m.loading {
		m.startMatrixPicker()
		return m, nil
	}
	if key == "esc" {
		if m.loadErr != nil && len(m.pages) > 0 {
			m.loadErr = nil
			m.failedMatrix = nil
			return m, nil
		}
		if len(m.pages) <= 1 || m.loading || m.loadErr != nil {
			return m, tea.Quit
		}
		m.goBack()
		return m, nil
	}
	if m.loading || m.loadErr != nil || len(m.pages) == 0 {
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
	case "/":
		return m, m.startSearch()
	}

	return m, nil
}

func (m *model) activateMatrix(matrix MatrixOption, cache attack.CacheData) {
	m.options.Matrix = matrix.Name
	m.options.CachePath = matrix.CachePath
	m.options.TacticOrder = append([]string(nil), matrix.TacticOrder...)
	m.cache = cache
	m.tactics = attack.CollectUniqueTactics(cache.Techniques, matrix.TacticOrder)
	m.pages = []page{m.explorePage()}
	m.loading = false
	m.loadingMatrix = nil
	m.loadErr = nil
	m.failedMatrix = nil
}

func (m *model) moveCursor(delta int) {
	active := m.activePage()
	if active == nil {
		return
	}
	if active.kind == pageDetail {
		active.offset = min(max(active.offset+delta, 0), m.detailMaxOffset(*active))
		return
	}
	if len(active.items) == 0 {
		return
	}
	active.cursor = min(max(active.cursor+delta, 0), len(active.items)-1)
}

func (m *model) selectCurrent() {
	active := m.activePage()
	if active == nil {
		return
	}
	if active.kind == pageDetail {
		m.openRelations(active.relations)
		return
	}
	item, ok := selectedPageItem(*active)
	if !ok {
		return
	}

	switch item.kind {
	case itemCategory:
		m.pushList(strings.ToUpper(item.name), m.itemsForCategory(item.id))
	case itemTactic:
		m.pushList("TECHNIQUES: "+strings.ToUpper(item.name), techniqueItems(attack.ListByTactic(m.cache.Techniques, item.id)))
	case itemRelation:
		m.pushList(strings.ToUpper(item.name), item.related)
	default:
		m.pages = append(m.pages, page{
			kind:      pageDetail,
			title:     "DETAILS",
			detail:    item,
			relations: m.relationItems(item),
		})
	}
}

func (m *model) openRelations(relations []browseItem) {
	switch len(relations) {
	case 0:
		return
	case 1:
		m.pushList(strings.ToUpper(relations[0].name), relations[0].related)
	default:
		m.pushList("MAPPINGS", relations)
	}
}

func (m *model) pushList(title string, items []browseItem) {
	m.pages = append(m.pages, page{kind: pageList, title: title, items: items})
}

func (m *model) goBack() {
	if len(m.pages) > 1 {
		m.pages = m.pages[:len(m.pages)-1]
	}
}

func (m *model) activePage() *page {
	if len(m.pages) == 0 {
		return nil
	}
	return &m.pages[len(m.pages)-1]
}

func selectedPageItem(current page) (browseItem, bool) {
	if current.kind != pageList || current.cursor < 0 || current.cursor >= len(current.items) {
		return browseItem{}, false
	}
	return current.items[current.cursor], true
}
