package tui

import (
	"fmt"
	"strings"

	"mitre-explorer/internal/attack"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

type searchScope struct {
	name   string
	target string
}

var searchScopes = []searchScope{
	{name: "All", target: "all"},
	{name: "Techniques", target: "techniques"},
	{name: "Groups", target: "groups"},
	{name: "Mitigations", target: "mitigations"},
	{name: "Software", target: "software"},
	{name: "Campaigns", target: "campaigns"},
	{name: "Detections", target: "detections"},
	{name: "Analytics", target: "analytics"},
	{name: "Data Components", target: "data-components"},
}

type searchState struct {
	input   textinput.Model
	active  bool
	scope   int
	results []browseItem
}

func newSearchState(plain bool) searchState {
	input := textinput.New()
	input.Prompt = "> "
	input.Placeholder = "name, ID, or description"
	input.CharLimit = 120
	input.SetWidth(52)

	styles := input.Styles()
	if plain {
		plainStyle := lipgloss.NewStyle()
		styles.Focused = textinput.StyleState{
			Text: plainStyle, Placeholder: plainStyle, Suggestion: plainStyle, Prompt: plainStyle,
		}
		styles.Blurred = styles.Focused
		styles.Cursor.Color = lipgloss.NoColor{}
	} else {
		styles.Focused.Prompt = lipgloss.NewStyle().Foreground(lipgloss.Color("#58C7D9"))
		styles.Focused.Placeholder = lipgloss.NewStyle().Foreground(lipgloss.Color("#80878F"))
		styles.Cursor.Color = lipgloss.Color("#58C7D9")
	}
	input.SetStyles(styles)
	return searchState{input: input}
}

func (m *model) startSearch() tea.Cmd {
	m.search.active = true
	m.search.scope = 0
	m.search.results = nil
	m.search.input.Reset()
	m.setSearchWidth()
	return m.search.input.Focus()
}

func (m *model) updateSearch(message tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch message.String() {
	case "ctrl+c":
		return *m, tea.Quit
	case "esc":
		m.search.input.Blur()
		m.search.active = false
		m.search.results = nil
		return *m, nil
	case "tab":
		m.search.scope = (m.search.scope + 1) % len(searchScopes)
		m.refreshSearch()
		return *m, nil
	case "shift+tab":
		m.search.scope = (m.search.scope - 1 + len(searchScopes)) % len(searchScopes)
		m.refreshSearch()
		return *m, nil
	case "enter":
		query := strings.TrimSpace(m.search.input.Value())
		if query == "" {
			return *m, nil
		}
		scope := searchScopes[m.search.scope]
		results := append([]browseItem(nil), m.search.results...)
		m.search.input.Blur()
		m.search.active = false
		m.search.results = nil
		m.pushList(fmt.Sprintf("SEARCH: %s [%s]", query, strings.ToUpper(scope.name)), results)
		return *m, nil
	}

	var command tea.Cmd
	m.search.input, command = m.search.input.Update(message)
	m.refreshSearch()
	return *m, command
}

func (m *model) refreshSearch() {
	query := strings.TrimSpace(m.search.input.Value())
	if query == "" {
		m.search.results = nil
		return
	}
	m.search.results = m.searchItems(query, searchScopes[m.search.scope].target)
}

func (m model) searchItems(query, target string) []browseItem {
	var items []browseItem
	if target == "all" || target == "techniques" {
		if exact, ok := attack.FindTechniqueByID(m.cache.Techniques, query); ok {
			return techniqueItems([]attack.Technique{exact})
		}
		techniques := attack.SearchTechniques(m.cache.Techniques, query, false, 0)
		items = append(items, techniqueItems(techniques)...)
	}
	if target == "techniques" {
		return items
	}

	results := attack.SearchEntities(m.cache, target, query, 0)
	var exactResults []attack.EntitySearchResult
	for _, result := range results {
		if result.ID != "" && strings.EqualFold(result.ID, query) {
			exactResults = append(exactResults, result)
		}
	}
	if len(exactResults) > 0 {
		results = exactResults
	}
	for _, result := range results {
		if item, ok := m.itemForSearchResult(result); ok {
			items = append(items, item)
		}
	}
	return items
}

func (m model) itemForSearchResult(result attack.EntitySearchResult) (browseItem, bool) {
	key := result.ID
	if key == "" {
		key = result.Name
	}
	switch result.Type {
	case "group":
		entity, ok := attack.FindGroup(m.cache, key)
		return groupItem(entity), ok
	case "mitigation":
		entity, ok := attack.FindMitigation(m.cache, key)
		return mitigationItem(entity), ok
	case "software":
		entity, ok := attack.FindSoftware(m.cache, key)
		return softwareItem(entity), ok
	case "campaign":
		entity, ok := attack.FindCampaign(m.cache, key)
		return campaignItem(entity), ok
	case "detection":
		entity, ok := attack.FindDetectionStrategy(m.cache, key)
		return detectionItem(entity), ok
	case "analytic":
		entity, ok := attack.FindAnalytic(m.cache, key)
		return analyticItem(entity), ok
	case "data-component":
		for _, entity := range m.cache.DataComponents {
			if strings.EqualFold(entity.ID, key) || strings.EqualFold(entity.StixID, key) || strings.EqualFold(entity.Name, result.Name) {
				return dataComponentItem(entity), true
			}
		}
	}
	return browseItem{}, false
}

func (m *model) setSearchWidth() {
	width := m.width
	if width == 0 {
		width = 100
	}
	m.search.input.SetWidth(min(max(width-20, 20), 60))
}
