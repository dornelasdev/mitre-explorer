package tui

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"mitre-explorer/internal/attack"

	tea "charm.land/bubbletea/v2"
)

func testCache() attack.CacheData {
	return attack.CacheData{
		Techniques: []attack.Technique{
			{ID: "T2000", Name: "Second Execution", Description: "Second description", Tactics: []string{"execution"}, Platforms: []string{"Linux"}},
			{ID: "T3000", Name: "Discovery Example", Description: "Discovery description", Tactics: []string{"discovery"}},
			{ID: "T1000", Name: "First Execution", Description: "First description", Tactics: []string{"execution"}, DataSources: []string{"Process"}},
		},
		Groups:              []attack.Group{{ID: "G0001", Name: "Example Group", Description: "Group description", Aliases: []string{"Example"}}},
		Mitigations:         []attack.Mitigation{{ID: "M0001", Name: "Example Mitigation", Description: "Mitigation description"}},
		Softwares:           []attack.Software{{ID: "S0001", Name: "Example Software", Type: "tool", Description: "Software description"}},
		Campaigns:           []attack.Campaign{{ID: "C0001", Name: "Example Campaign", Description: "Campaign description"}},
		DetectionStrategies: []attack.DetectionStrategy{{ID: "DET0001", StixID: "x-mitre-detection-strategy--1", Name: "Example Detection", Description: "Detection description", Analytics: []string{"AN0001"}}},
		Analytics:           []attack.Analytic{{ID: "AN0001", StixID: "x-mitre-analytic--1", Name: "Example Analytic", Description: "Analytic description", DataComponents: []string{"DC0001"}}},
		DataComponents:      []attack.DataComponent{{ID: "DC0001", StixID: "x-mitre-data-component--1", Name: "Process Creation", Description: "Component description"}},
		Relationships: []attack.Relationship{
			{Type: "uses", SourceType: "group", SourceID: "G0001", TargetType: "technique", TargetID: "T1000"},
			{Type: "mitigates", SourceType: "mitigation", SourceID: "M0001", TargetType: "technique", TargetID: "T1000"},
			{Type: "uses", SourceType: "software", SourceID: "S0001", TargetType: "technique", TargetID: "T1000"},
			{Type: "uses", SourceType: "campaign", SourceID: "C0001", TargetType: "technique", TargetID: "T1000"},
			{Type: "detects", SourceType: "detection_strategy", SourceID: "DET0001", TargetType: "technique", TargetID: "T1000"},
			{Type: "has_data_component", SourceType: "technique", SourceID: "T1000", TargetType: "data_component", TargetID: "DC0001"},
		},
	}
}

func testOptions(path string) Options {
	return Options{
		Matrix:      "enterprise",
		CachePath:   path,
		TacticOrder: []string{"Discovery", "Execution"},
		Version:     "test",
		Plain:       true,
	}
}

func loadedTestModel() model {
	m := newModel(testOptions("data/cache.json"))
	updated, _ := m.Update(cacheLoadedMsg{cache: testCache()})
	return updated.(model)
}

func sendKey(m model, key tea.KeyPressMsg) (model, tea.Cmd) {
	updated, command := m.Update(key)
	return updated.(model), command
}

func TestInitLoadsCacheAndExploreCategories(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	if err := attack.SaveCacheData(path, testCache()); err != nil {
		t.Fatal(err)
	}

	m := newModel(testOptions(path))
	updated, _ := m.Update(m.Init()())
	got := updated.(model)
	active := got.activePage()
	if got.loading || got.loadErr != nil || len(got.tactics) != 2 || active == nil || len(active.items) != 8 {
		t.Fatalf("cache did not initialize explorer: loading=%v err=%v tactics=%v page=%+v", got.loading, got.loadErr, got.tactics, active)
	}
	if got.tactics[0] != "Discovery" || active.items[0].name != "Tactics" || active.items[7].name != "Data Components" {
		t.Fatalf("unexpected explorer order: tactics=%v categories=%v", got.tactics, active.items)
	}
}

func TestMissingCacheShowsRecoveryCommand(t *testing.T) {
	m := newModel(testOptions(filepath.Join(t.TempDir(), "missing.json")))
	updated, _ := m.Update(m.Init()())
	got := updated.(model)
	got.width, got.height = 90, 24
	view := got.View().Content
	if got.loadErr == nil || !strings.Contains(view, "CACHE UNAVAILABLE") || !strings.Contains(view, "go run . update --matrix enterprise") {
		t.Fatalf("missing cache guidance not rendered:\n%s", view)
	}
}

func TestTacticTechniqueDetailNavigation(t *testing.T) {
	m := loadedTestModel()
	m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if active := m.activePage(); active == nil || active.title != "TACTICS" {
		t.Fatalf("tactics page not opened: %+v", active)
	}

	m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyDown})
	m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyDown})
	if m.activePage().cursor != 1 {
		t.Fatalf("cursor moved beyond last tactic: %d", m.activePage().cursor)
	}
	m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyEnter})
	active := m.activePage()
	if active.title != "TECHNIQUES: EXECUTION" || len(active.items) != 2 || active.items[0].id != "T1000" {
		t.Fatalf("technique page not selected correctly: %+v", active)
	}

	m, _ = sendKey(m, tea.KeyPressMsg{Code: 'j', Text: "j"})
	m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyEnter})
	active = m.activePage()
	if active.kind != pageDetail || active.detail.id != "T2000" || !strings.Contains(m.View().Content, "Second description") {
		t.Fatalf("detail page not selected correctly: %+v", active)
	}

	m, _ = sendKey(m, tea.KeyPressMsg{Code: 'b', Text: "b"})
	if active = m.activePage(); active.title != "TECHNIQUES: EXECUTION" || active.cursor != 1 {
		t.Fatal("back did not preserve technique selection")
	}
	m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyEscape})
	if active = m.activePage(); active.title != "TACTICS" || active.cursor != 1 {
		t.Fatal("escape did not preserve tactic selection")
	}
	m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyEscape})
	if active = m.activePage(); active.title != "EXPLORE" {
		t.Fatal("escape did not return to explorer root")
	}
	_, command := sendKey(m, tea.KeyPressMsg{Code: tea.KeyEscape})
	if command == nil {
		t.Fatal("escape at the explorer root did not quit")
	}
}

func TestEntityRelationshipsUseGenericPages(t *testing.T) {
	m := loadedTestModel()
	tests := []struct {
		category string
		want     []string
	}{
		{"groups", []string{"Mapped Techniques:1"}},
		{"mitigations", []string{"Mitigated Techniques:1"}},
		{"software", []string{"Mapped Techniques:1"}},
		{"campaigns", []string{"Mapped Techniques:1"}},
		{"detections", []string{"Detected Techniques:1", "Analytics:1", "Data Components:1"}},
		{"analytics", []string{"Data Components:1"}},
		{"data-components", []string{"Mapped Techniques:1"}},
	}

	for _, test := range tests {
		t.Run(test.category, func(t *testing.T) {
			items := m.itemsForCategory(test.category)
			if len(items) != 1 {
				t.Fatalf("%s items = %d", test.category, len(items))
			}
			relations := m.relationItems(items[0])
			if len(relations) != len(test.want) {
				t.Fatalf("%s relations = %+v", test.category, relations)
			}
			for index, want := range test.want {
				got := relations[index].name + ":" + strconv.Itoa(relations[index].count)
				if got != want {
					t.Fatalf("relation %d = %q, want %q", index, got, want)
				}
			}
		})
	}
}

func TestDetectionMappingNavigation(t *testing.T) {
	m := loadedTestModel()
	m.activePage().cursor = 5
	m.selectCurrent()
	m.selectCurrent()
	if active := m.activePage(); active.kind != pageDetail || len(active.relations) != 3 {
		t.Fatalf("detection details missing mappings: %+v", active)
	}
	m.selectCurrent()
	if active := m.activePage(); active.title != "MAPPINGS" || len(active.items) != 3 {
		t.Fatalf("mapping chooser not opened: %+v", active)
	}
	m.activePage().cursor = 1
	m.selectCurrent()
	if active := m.activePage(); active.title != "ANALYTICS" || len(active.items) != 1 || active.items[0].id != "AN0001" {
		t.Fatalf("analytic mapping not opened: %+v", active)
	}
}

func TestDetailScrollingStopsAtContentBounds(t *testing.T) {
	m := loadedTestModel()
	m.width, m.height = 80, 18
	m.activePage().cursor = 1
	m.selectCurrent()
	m.selectCurrent()
	m.activePage().detail.description = strings.Repeat("Long description line.\n", 30)

	m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyDown})
	if m.activePage().offset != 1 {
		t.Fatalf("detail did not scroll down: %d", m.activePage().offset)
	}
	for range 100 {
		m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyDown})
	}
	if got, maxOffset := m.activePage().offset, m.detailMaxOffset(*m.activePage()); got != maxOffset {
		t.Fatalf("detail offset = %d, want maximum %d", got, maxOffset)
	}
	for range 100 {
		m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyUp})
	}
	if m.activePage().offset != 0 {
		t.Fatalf("detail moved above first line: %d", m.activePage().offset)
	}
}

func TestSearchInputScopeAndCancellation(t *testing.T) {
	m := loadedTestModel()
	m.activePage().cursor = 4
	var command tea.Cmd
	m, command = sendKey(m, tea.KeyPressMsg{Code: '/', Text: "/"})
	if !m.search.active || !m.search.input.Focused() || command == nil {
		t.Fatal("search input did not open and receive focus")
	}

	m, command = sendKey(m, tea.KeyPressMsg{Code: 'q', Text: "q"})
	if command != nil {
		_ = command()
	}
	if !m.search.active || m.search.input.Value() != "q" {
		t.Fatalf("q did not remain search text: active=%v value=%q", m.search.active, m.search.input.Value())
	}
	m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyTab})
	if m.search.scope != 1 || searchScopes[m.search.scope].name != "Techniques" {
		t.Fatalf("scope did not advance: %d", m.search.scope)
	}
	m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift})
	if m.search.scope != 0 {
		t.Fatalf("scope did not move backward: %d", m.search.scope)
	}

	m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyEscape})
	if m.search.active || m.activePage().title != "EXPLORE" || m.activePage().cursor != 4 {
		t.Fatal("search cancellation changed the current page")
	}
}

func TestSearchExactTechniqueIDAndResultNavigation(t *testing.T) {
	m := loadedTestModel()
	m.cache.Techniques[0].Description = "This description references T1000."
	m, _ = sendKey(m, tea.KeyPressMsg{Code: '/', Text: "/"})
	m.search.input.SetValue("T1000")
	m.refreshSearch()
	if len(m.search.results) != 1 || m.search.results[0].kind != itemTechnique || m.search.results[0].id != "T1000" {
		t.Fatalf("exact technique search = %+v", m.search.results)
	}
	if view := m.View().Content; !strings.Contains(view, "Scope: All") || !strings.Contains(view, "1 result(s)") {
		t.Fatalf("live search summary missing:\n%s", view)
	}

	m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if m.search.active || m.activePage().title != "SEARCH: T1000 [ALL]" || len(m.activePage().items) != 1 {
		t.Fatalf("search results page not opened: %+v", m.activePage())
	}
	m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if m.activePage().kind != pageDetail || m.activePage().detail.id != "T1000" {
		t.Fatalf("search result details not opened: %+v", m.activePage())
	}
}

func TestScopedEntitySearchRetainsMappings(t *testing.T) {
	m := loadedTestModel()
	m.startSearch()
	m.search.scope = 2
	m.search.input.SetValue("Example Group")
	m.refreshSearch()
	if len(m.search.results) != 1 || m.search.results[0].kind != itemGroup {
		t.Fatalf("group search = %+v", m.search.results)
	}
	m.updateSearch(tea.KeyPressMsg{Code: tea.KeyEnter})
	m.selectCurrent()
	if active := m.activePage(); active.kind != pageDetail || len(active.relations) != 1 || active.relations[0].count != 1 {
		t.Fatalf("searched group lost mappings: %+v", active)
	}
}

func TestSearchEmptyAndNoResults(t *testing.T) {
	m := loadedTestModel()
	m.startSearch()
	m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if !m.search.active || len(m.pages) != 1 {
		t.Fatal("empty search unexpectedly opened a results page")
	}

	m.search.input.SetValue("does-not-exist")
	m.refreshSearch()
	m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if m.search.active || m.activePage().kind != pageList || len(m.activePage().items) != 0 {
		t.Fatalf("no-result search page = %+v", m.activePage())
	}
}

func TestViewAdaptsToTerminalSize(t *testing.T) {
	tests := []struct {
		name      string
		width     int
		height    int
		want      []string
		doNotWant string
	}{
		{name: "wide", width: 110, height: 30, want: []string{"__  __", "EXPLORE", "Tactics (2)", "Matrix: enterprise"}},
		{name: "compact", width: 60, height: 16, want: []string{"MITRE EXPLORER", "EXPLORE", "Tactics (2)"}, doNotWant: "__  __"},
		{name: "small", width: 30, height: 8, want: []string{"Terminal too small", "30x8", "q/Esc"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := loadedTestModel()
			updated, _ := m.Update(tea.WindowSizeMsg{Width: test.width, Height: test.height})
			view := updated.(model).View()
			if !view.AltScreen || view.WindowTitle != "MITRE Explorer" {
				t.Fatalf("unexpected view settings: alt=%v title=%q", view.AltScreen, view.WindowTitle)
			}
			for _, want := range test.want {
				if !strings.Contains(view.Content, want) {
					t.Fatalf("view missing %q:\n%s", want, view.Content)
				}
			}
			if test.doNotWant != "" && strings.Contains(view.Content, test.doNotWant) {
				t.Fatalf("view unexpectedly contains %q:\n%s", test.doNotWant, view.Content)
			}
		})
	}
}

func TestVisibleRangeKeepsCursorOnScreen(t *testing.T) {
	if start, end := visibleRange(20, 0, 5); start != 0 || end != 5 {
		t.Fatalf("first window = %d:%d", start, end)
	}
	if start, end := visibleRange(20, 10, 5); start > 10 || end <= 10 {
		t.Fatalf("middle window excludes cursor: %d:%d", start, end)
	}
	if start, end := visibleRange(20, 19, 5); start != 15 || end != 20 {
		t.Fatalf("last window = %d:%d", start, end)
	}
}

func TestQuitKeys(t *testing.T) {
	keys := []tea.KeyPressMsg{{Code: 'q', Text: "q"}, {Code: tea.KeyEscape}, {Code: 'c', Mod: tea.ModCtrl}}
	for _, key := range keys {
		_, command := newModel(Options{}).Update(key)
		if command == nil {
			t.Fatalf("key %q did not return a quit command", key.String())
		}
		if _, ok := command().(tea.QuitMsg); !ok {
			t.Fatalf("key %q returned a non-quit command", key.String())
		}
	}
}
