package tui

import (
	"strings"
	"testing"

	"mitre-explorer/internal/attack"
)

func TestEntityConnectionNavigation(t *testing.T) {
	for _, tc := range []struct {
		category         string
		forward, reverse int
		source, target   string
		kind             itemKind
	}{
		{"groups", 1, 1, "G0001", "S0001", itemSoftware},
		{"groups", 2, 2, "G0001", "C0001", itemCampaign},
		{"software", 1, 1, "S0001", "G0001", itemGroup},
		{"software", 2, 1, "S0001", "C0001", itemCampaign},
		{"campaigns", 1, 2, "C0001", "S0001", itemSoftware},
		{"campaigns", 2, 2, "C0001", "G0001", itemGroup},
	} {
		t.Run(tc.source+" to "+tc.target, func(t *testing.T) {
			m := loadedTestModel()
			m.width, m.height = 120, 40
			m.cache.Relationships = append(m.cache.Relationships,
				attack.Relationship{Type: "uses", SourceType: "group", SourceID: "G0001", TargetType: "software", TargetID: "S0001"},
				attack.Relationship{Type: "uses", SourceType: "campaign", SourceID: "C0001", TargetType: "software", TargetID: "S0001"},
				attack.Relationship{Type: "attributed-to", SourceType: "campaign", SourceID: "C0001", TargetType: "group", TargetID: "G0001"},
			)
			m.pushList(strings.ToUpper(tc.category), m.itemsForCategory(tc.category))
			m.selectCurrent()
			m.selectCurrent()
			if active := m.activePage(); active.title != "MAPPINGS" || len(active.items) != 3 {
				t.Fatalf("connection chooser missing: %+v", active)
			}
			m.activePage().cursor = tc.forward
			m.selectCurrent()
			if active := m.activePage(); len(active.items) != 1 || active.items[0].id != tc.target {
				t.Fatalf("incorrect connection list: %+v", active)
			}
			m.selectCurrent()
			if active := m.activePage(); active.kind != pageDetail || active.detail.kind != tc.kind || active.detail.id != tc.target || !strings.Contains(m.contextContent(), tc.target) {
				t.Fatalf("connection detail missing: %+v", active)
			}
			m.selectCurrent()
			m.activePage().cursor = tc.reverse
			m.selectCurrent()
			if active := m.activePage(); len(active.items) != 1 || active.items[0].id != tc.source {
				t.Fatalf("reverse connection missing: %+v", active)
			}
			for len(m.pages) > 4 {
				m.goBack()
			}
			if active := m.activePage(); active.title != "MAPPINGS" || active.cursor != tc.forward {
				t.Fatalf("back lost connection selection: %+v", active)
			}
			m.goBack()
			m.goBack()
			if active := m.activePage(); active.title != strings.ToUpper(tc.category) || active.cursor != 0 {
				t.Fatalf("back lost original list: %+v", active)
			}
		})
	}
}

func TestEmptyEntityConnectionsKeepBackNavigation(t *testing.T) {
	for _, category := range []string{"groups", "software", "campaigns"} {
		for _, index := range []int{1, 2} {
			m := loadedTestModel()
			m.pushList(category, m.itemsForCategory(category))
			m.selectCurrent()
			m.selectCurrent()
			m.activePage().cursor = index
			m.selectCurrent()
			if len(m.activePage().items) != 0 || !strings.Contains(m.contextContent(), "Nothing is available") {
				t.Fatalf("empty %s connection not shown: %+v", category, m.activePage())
			}
			m.goBack()
			if m.activePage().title != "MAPPINGS" || m.activePage().cursor != index {
				t.Fatal("empty connection lost back navigation")
			}
		}
	}
}
