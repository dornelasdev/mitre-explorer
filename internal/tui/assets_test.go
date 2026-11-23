package tui

import (
	"path/filepath"
	"strings"
	"testing"

	"mitre-explorer/internal/attack"

	tea "charm.land/bubbletea/v2"
)

func TestICSAssetNavigationAndSearch(t *testing.T) {
	cache, err := attack.BuildCacheDataFromSTIX(filepath.Join("..", "attack", "testdata", "ics-assets.json"))
	if err != nil {
		t.Fatal(err)
	}
	m := loadedTestModel()
	m.activateMatrix(MatrixOption{Name: "ics"}, cache)
	root := m.activePage()
	if len(root.items) != 9 || root.items[8].id != "assets" || root.items[8].count != 3 {
		t.Fatalf("ICS Assets category missing: %+v", root.items)
	}
	root.cursor = 8
	m.selectCurrent()
	if active := m.activePage(); active.title != "ASSETS" || len(active.items) != 3 || active.items[0].id != "A0001" {
		t.Fatalf("asset list not opened: %+v", active)
	}
	m.selectCurrent()
	for _, want := range []string{"ASSET DETAILS", "Platforms: Embedded, Linux", "Sectors: General", "Related Asset Examples:", "Monitoring Workstation (sectors: Water)", "Enter: Mapped Techniques (2)"} {
		if detail := m.contextContent(); !strings.Contains(detail, want) {
			t.Fatalf("missing %q:\n%s", want, detail)
		}
	}
	m.selectCurrent()
	if active := m.activePage(); len(active.items) != 2 || active.items[0].id != "T0001" {
		t.Fatalf("asset's mapped techniques not opened: %+v", active)
	}
	m.selectCurrent()
	m.selectCurrent()
	mappings := m.activePage()
	if mappings.title != "MAPPINGS" || len(mappings.items) != 7 || mappings.items[6].name != "Targeted Assets" {
		t.Fatalf("reverse asset mapping missing: %+v", mappings)
	}
	mappings.cursor = 6
	m.selectCurrent()
	if active := m.activePage(); active.title != "TARGETED ASSETS" || len(active.items) != 2 || active.items[0].id != "A0001" || active.items[1].id != "A0002" {
		t.Fatalf("unexpected reverse mapping: %+v", active)
	}
	m.selectCurrent()
	m.goBack()
	m.goBack()
	if active := m.activePage(); active.title != "MAPPINGS" || active.cursor != 6 {
		t.Fatalf("back lost asset-mapping selection: %+v", active)
	}

	m, _ = sendKey(m, tea.KeyPressMsg{Code: '/', Text: "/"})
	m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift})
	m.search.input.SetValue("A0001")
	m.refreshSearch()
	if !strings.Contains(m.searchContent(), "Scope: Assets") || len(m.search.results) != 1 {
		t.Fatalf("asset scope or search result missing:\n%s", m.searchContent())
	}
	m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyEnter})
	m.selectCurrent()
	if active := m.activePage(); active.detail.kind != itemAsset || active.detail.id != "A0001" {
		t.Fatalf("search failed to open asset detail: %+v", active)
	}
}

func TestAssetUIIsScopedAndLegacyCacheShowsHint(t *testing.T) {
	m := loadedTestModel()
	for _, matrix := range []string{"enterprise", "mobile", "ics"} {
		m.activateMatrix(MatrixOption{Name: matrix}, testCache())
		var category, scope bool
		for _, item := range m.activePage().items {
			category = category || item.id == "assets"
		}
		for _, item := range m.availableSearchScopes() {
			scope = scope || item.target == "assets"
		}
		want := matrix == "ics"
		if category != want || scope != want {
			t.Fatalf("%s asset availability: category=%v scope=%v", matrix, category, scope)
		}
		if want {
			m.activePage().cursor = 8
			m.selectCurrent()
			if !strings.Contains(m.contextContent(), "update --rebuild --matrix ics") {
				t.Fatal("legacy cache view lacks rebuild hint")
			}
			if !strings.Contains(m.leftPanel(10, 50), "No cached assets.") {
				t.Fatal("compact legacy cache view lacks a hint")
			}
		}
	}
}
