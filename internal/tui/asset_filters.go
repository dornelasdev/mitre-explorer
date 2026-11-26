package tui

import (
	"slices"

	"mitre-explorer/internal/attack"

	tea "charm.land/bubbletea/v2"
)

type assetFilterPicker struct {
	active   bool
	field    int
	values   [2][]string
	selected [2]int
}

func (m model) canFilterAssets(current *page) bool {
	return current != nil && current.assetList && m.options.Matrix == "ics" && len(m.cache.Assets) > 0
}

func (m *model) startAssetFilterPicker() {
	current := m.activePage()
	if !m.canFilterAssets(current) {
		return
	}
	sectors, platforms := attack.AssetFilterValues(m.cache.Assets)
	picker := assetFilterPicker{
		active: true,
		values: [2][]string{append([]string{""}, sectors...), append([]string{""}, platforms...)},
	}
	picker.selected[0] = max(0, slices.Index(picker.values[0], current.filters.Sector))
	picker.selected[1] = max(0, slices.Index(picker.values[1], current.filters.Platform))
	m.assetPicker = picker
}

func (m model) updateAssetFilterPicker(key string) (tea.Model, tea.Cmd) {
	picker := &m.assetPicker
	switch key {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "esc", "b", "f":
		m.assetPicker = assetFilterPicker{}
	case "tab", "shift+tab", "up", "down", "k", "j":
		picker.field = 1 - picker.field
	case "left", "right":
		n := len(picker.values[picker.field])
		delta := 1
		if key == "left" {
			delta = -1
		}
		picker.selected[picker.field] = (picker.selected[picker.field] + delta + n) % n
	case "enter":
		m.applyAssetFilters(attack.AssetFilters{
			Sector:   picker.values[0][picker.selected[0]],
			Platform: picker.values[1][picker.selected[1]],
		})
		m.assetPicker = assetFilterPicker{}
	}
	return m, nil
}

func (m *model) applyAssetFilters(filters attack.AssetFilters) {
	current := m.activePage()
	if !m.canFilterAssets(current) || current.filters == filters {
		return
	}
	current.filters = filters
	current.items = assetBrowseItems(m.cache.Assets, filters)
	current.cursor = 0
}
