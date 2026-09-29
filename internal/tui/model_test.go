package tui

import (
	"path/filepath"
	"strings"
	"testing"

	"mitre-explorer/internal/attack"

	tea "charm.land/bubbletea/v2"
)

func testCache() attack.CacheData {
	return attack.CacheData{Techniques: []attack.Technique{
		{ID: "T2000", Name: "Second Execution", Description: "Second description", Tactics: []string{"execution"}, Platforms: []string{"Linux"}},
		{ID: "T3000", Name: "Discovery Example", Description: "Discovery description", Tactics: []string{"discovery"}},
		{ID: "T1000", Name: "First Execution", Description: "First description", Tactics: []string{"execution"}, DataSources: []string{"Process"}},
	}}
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

func TestInitLoadsCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	if err := attack.SaveCacheData(path, testCache()); err != nil {
		t.Fatal(err)
	}

	m := newModel(testOptions(path))
	message := m.Init()()
	updated, _ := m.Update(message)
	got := updated.(model)
	if got.loading || got.loadErr != nil || len(got.tactics) != 2 {
		t.Fatalf("cache did not load: loading=%v err=%v tactics=%v", got.loading, got.loadErr, got.tactics)
	}
	if got.tactics[0] != "Discovery" || got.tactics[1] != "Execution" {
		t.Fatalf("unexpected tactic order: %v", got.tactics)
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

	m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyUp})
	if m.tacticCursor != 0 {
		t.Fatalf("cursor moved above first tactic: %d", m.tacticCursor)
	}
	m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyDown})
	m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyDown})
	if m.tacticCursor != 1 {
		t.Fatalf("cursor moved beyond last tactic: %d", m.tacticCursor)
	}

	m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if m.screen != screenTechniques || len(m.techniques) != 2 || m.techniques[0].ID != "T1000" {
		t.Fatalf("technique screen not selected correctly: screen=%v techniques=%v", m.screen, m.techniques)
	}
	m, _ = sendKey(m, tea.KeyPressMsg{Code: 'j', Text: "j"})
	m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyEnter})
	selected, ok := m.selectedTechnique()
	if m.screen != screenTechniqueDetail || !ok || selected.ID != "T2000" {
		t.Fatalf("detail screen not selected correctly: screen=%v selected=%+v", m.screen, selected)
	}
	if !strings.Contains(m.View().Content, "Second description") {
		t.Fatal("selected technique details were not rendered")
	}

	m, _ = sendKey(m, tea.KeyPressMsg{Code: 'b', Text: "b"})
	if m.screen != screenTechniques || m.techniqueCursor != 1 {
		t.Fatal("back did not preserve technique selection")
	}
	m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyEscape})
	if m.screen != screenTactics || m.tacticCursor != 1 {
		t.Fatal("escape did not return to the selected tactic")
	}
	_, command := sendKey(m, tea.KeyPressMsg{Code: tea.KeyEscape})
	if command == nil {
		t.Fatal("escape at the tactic root did not quit")
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
		{
			name:   "wide",
			width:  110,
			height: 30,
			want:   []string{"__  __", "TACTICS", "Discovery", "Matrix: enterprise"},
		},
		{
			name:      "compact",
			width:     60,
			height:    16,
			want:      []string{"MITRE EXPLORER", "TACTICS", "Discovery"},
			doNotWant: "__  __",
		},
		{
			name:   "small",
			width:  30,
			height: 8,
			want:   []string{"Terminal too small", "30x8", "q/Esc"},
		},
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
	keys := []tea.KeyPressMsg{
		{Code: 'q', Text: "q"},
		{Code: tea.KeyEscape},
		{Code: 'c', Mod: tea.ModCtrl},
	}

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
