package tui

import (
	"strings"
	"testing"

	"mitre-explorer/internal/attack"

	tea "charm.land/bubbletea/v2"
)

func TestICSAssetFilterPicker(t *testing.T) {
	cache := testCache()
	cache.Assets = []attack.Asset{
		{ID: "A0001", Name: "Example controller", Sectors: []string{"General"}, Platforms: []string{"Linux"}},
		{ID: "A0002", Name: "Example workstation", Sectors: []string{"Water and Wastewater"}, Platforms: []string{"Windows"}},
	}
	m := loadedTestModel()
	m.activateMatrix(MatrixOption{Name: "ics"}, cache)
	m.activePage().cursor = 8
	m.selectCurrent()
	key := func(code rune) {
		m, _ = sendKey(m, tea.KeyPressMsg{Code: code})
	}
	if text := m.footer(80); !strings.Contains(text, "f filters") || !strings.Contains(text, "c clear") {
		t.Fatalf("asset list controls not discoverable: %s", text)
	}
	key('f')
	for _, size := range [][2]int{{100, 30}, {55, 14}} {
		m.width, m.height = size[0], size[1]
		view := m.View().Content
		for _, want := range []string{"ASSET FILTERS", "Sector: Any", "Platform: Any", "Enter apply"} {
			if !strings.Contains(view, want) {
				t.Fatalf("size %v: picker missing %q:\n%s", size, want, view)
			}
		}
	}
	key(tea.KeyRight) // General.
	key(tea.KeyTab)
	key(tea.KeyRight) // Linux.
	key(tea.KeyEnter)
	page := m.activePage()
	if m.assetPicker.active || len(page.items) != 1 || page.items[0].id != "A0001" || page.filters != (attack.AssetFilters{Sector: "General", Platform: "Linux"}) {
		t.Fatalf("combined filters not applied: %+v", page)
	}
	view := m.View().Content
	for _, want := range []string{"Sector: General", "Platform: Linux", "A0001"} {
		if !strings.Contains(view, want) {
			t.Fatalf("active list missing %q:\n%s", want, view)
		}
	}
	key(tea.KeyEnter)
	key(tea.KeyEscape)
	if got := m.activePage().filters; got != (attack.AssetFilters{Sector: "General", Platform: "Linux"}) {
		t.Fatalf("opening a detail lost filters: %+v", got)
	}
	if found := m.searchItems("A0002", "assets"); len(found) != 1 {
		t.Fatal("asset list filters leaked into search")
	}
	key('f')
	key(tea.KeyRight) // Draft Water and Wastewater.
	m.width, m.height = 36, 10
	if narrow := m.View().Content; !strings.Contains(narrow, "Sector: Water and") || !strings.Contains(narrow, "Platform: Linux") {
		t.Fatalf("long sector hid a picker field in a narrow terminal:\n%s", narrow)
	}
	key(tea.KeyEscape)
	if m.assetPicker.active || m.activePage().filters.Sector != "General" {
		t.Fatal("Esc applied a draft filter")
	}
	key('f')
	key(tea.KeyTab)
	key(tea.KeyRight) // Windows with General has no matches.
	key(tea.KeyEnter)
	if len(m.activePage().items) != 0 || !strings.Contains(m.leftPanel(8, 46), "No assets match filters.") {
		t.Fatal("empty combination not indicated")
	}
	key('c')
	if len(m.activePage().items) != 2 || m.activePage().filters != (attack.AssetFilters{}) {
		t.Fatal("clear did not restore the full asset list")
	}
}

func TestAssetFiltersOnlyApplyToAssetsCategory(t *testing.T) {
	m := loadedTestModel()
	cache := testCache()
	cache.Assets = []attack.Asset{{ID: "A0001", Sectors: []string{"General"}}}
	m.activateMatrix(MatrixOption{Name: "ics"}, cache)
	for _, title := range []string{"TARGETED ASSETS", "SEARCH: A0001 [ASSETS]"} {
		m.pushList(title, assetBrowseItems(cache.Assets, attack.AssetFilters{}))
		m, _ = sendKey(m, tea.KeyPressMsg{Code: 'f'})
		if m.assetPicker.active || m.canFilterAssets(m.activePage()) {
			t.Fatalf("filters became active outside the root asset list: %s", title)
		}
		m.goBack()
	}
	m.activateMatrix(MatrixOption{Name: "ics"}, testCache())
	m.activePage().cursor = 8
	m.selectCurrent()
	m, _ = sendKey(m, tea.KeyPressMsg{Code: 'f'})
	if m.assetPicker.active || !strings.Contains(m.contextContent(), "update --rebuild --matrix ics") {
		t.Fatal("missing cache should show a rebuild hint rather than opening the picker")
	}
}
