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
	cache attack.CacheData
}

type cacheLoadFailedMsg struct {
	err error
}

type model struct {
	options Options
	cache   attack.CacheData
	tactics []string
	pages   []page
	search  searchState
	width   int
	height  int
	loading bool
	loadErr error
}

func newModel(options Options) model {
	return model{options: options, search: newSearchState(options.Plain), loading: true}
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
		m.setSearchWidth()
	case cacheLoadedMsg:
		m.cache = message.cache
		m.tactics = attack.CollectUniqueTactics(m.cache.Techniques, m.options.TacticOrder)
		m.loading = false
		m.loadErr = nil
		m.pages = []page{m.explorePage()}
	case cacheLoadFailedMsg:
		m.loading = false
		m.loadErr = message.err
	case tea.KeyPressMsg:
		if m.search.active {
			return m.updateSearch(message)
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
	if key == "esc" {
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
