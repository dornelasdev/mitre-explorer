package tui

import (
	"strings"
	"testing"

	"mitre-explorer/internal/attack"

	tea "charm.land/bubbletea/v2"
)

func TestReferenceWarningsSurviveDetailAndMappingNavigation(t *testing.T) {
	for _, partial := range []bool{false, true} {
		name := "unresolved"
		if partial {
			name = "partial"
		}
		t.Run(name, func(t *testing.T) {
			cache := testCache()
			cache.Analytics[0].DataComponents = []string{"missing-component"}
			if partial {
				cache.Analytics[0].DataComponents = append(cache.Analytics[0].DataComponents, "DC0001")
			}
			m := newModel(testOptions("data/cache.json"))
			updated, _ := m.Update(cacheLoadedMsg{cache: cache})
			m = updated.(model)
			m.width, m.height = 120, 40
			m.pages[0].cursor = 6 // Analytics.
			m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyEnter})
			m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyEnter})
			if detail := m.contextContent(); !strings.Contains(detail, "UNRESOLVED REFERENCES") || !strings.Contains(detail, "AN0001 -> data component missing-component") {
				t.Fatalf("detail lacks diagnostic:\n%s", detail)
			}
			m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyEnter})
			active := m.activePage()
			if len(active.issues) != 1 || len(active.items) != map[bool]int{false: 0, true: 1}[partial] {
				t.Fatalf("mapping lost warnings or resolved results: %+v", active)
			}
			for _, width := range []int{60, 120} {
				m.width = width
				view := m.View().Content
				if !strings.Contains(view, "Incomplete:") {
					t.Fatalf("width %d: mapping warning missing:\n%s", width, view)
				}
				if !partial && (!strings.Contains(view, "No resolved items.") || strings.Contains(view, "No items found.")) {
					t.Fatalf("width %d: unresolved mapping shown as empty:\n%s", width, view)
				}
			}
			m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyEscape})
			if m.activePage().kind != pageDetail || len(m.activePage().detail.issues) != 1 {
				t.Fatal("back navigation lost the detail warning")
			}
		})
	}
}

func TestDetectionRelationWarningsAreScoped(t *testing.T) {
	m := loadedTestModel()
	m.cache.Analytics[0].DataComponents = append(m.cache.Analytics[0].DataComponents, "missing-component")
	m.cache.DetectionStrategies[0].Analytics = append(m.cache.DetectionStrategies[0].Analytics, "missing-analytic")
	relations := m.relationItems(detectionItem(m.cache.DetectionStrategies[0]))
	if len(relations[0].issues) != 0 || len(relations[1].issues) != 1 || len(relations[2].issues) != 2 {
		t.Fatalf("warnings leaked into unrelated mapping types: %+v", relations)
	}
	if !strings.Contains(itemLabel(relations[2]), "1 resolved; incomplete") {
		t.Fatalf("mapping label hides partial results: %s", itemLabel(relations[2]))
	}
	m.cache.Analytics[0].DataComponents = nil
	m.cache.DetectionStrategies[0].Analytics = nil
	if issues := m.itemReferenceIssues(analyticItem(m.cache.Analytics[0])); len(issues) != 0 {
		t.Fatal("an empty reference list was treated as unresolved")
	}
	if issues := attack.CacheReferenceIssues(m.cache); len(issues) != 0 {
		t.Fatalf("empty mappings produced issues: %+v", issues)
	}
}
