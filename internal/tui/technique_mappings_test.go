package tui

import (
	"strings"
	"testing"

	"mitre-explorer/internal/attack"
)

func TestTechniqueReverseMappingPages(t *testing.T) {
	for _, tc := range []struct {
		name     string
		relation int
		id       string
		kind     itemKind
	}{
		{"groups", 0, "G0001", itemGroup}, {"software", 1, "S0001", itemSoftware},
		{"campaigns", 2, "C0001", itemCampaign}, {"mitigations", 3, "M0001", itemMitigation},
		{"detections", 4, "DET0001", itemDetection},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := loadedTestModel()
			m.width, m.height = 120, 40
			m.pushList("TECHNIQUES", techniqueItems(m.cache.Techniques))
			m.activePage().cursor = 2 // T1000 carries all five reverse relationships.
			m.selectCurrent()
			if active := m.activePage(); active.kind != pageDetail || len(active.relations) != 5 {
				t.Fatalf("technique detail lacks mappings: %+v", active)
			}
			m.selectCurrent()
			m.activePage().cursor = tc.relation
			m.selectCurrent()
			if active := m.activePage(); len(active.items) != 1 || active.items[0].id != tc.id {
				t.Fatalf("wrong reverse mapping: %+v", active)
			}
			m.selectCurrent()
			if active := m.activePage(); active.detail.kind != tc.kind || active.detail.id != tc.id || !strings.Contains(m.contextContent(), tc.id) {
				t.Fatalf("mapped object details not opened: %+v", active)
			}
			// Follow the mapped object back to the same technique using its forward mapping.
			m.selectCurrent()
			if tc.kind == itemDetection {
				m.selectCurrent()
			}
			if active := m.activePage(); len(active.items) != 1 || active.items[0].id != "T1000" {
				t.Fatalf("mapped object's existing navigation broke: %+v", active)
			}
			for len(m.pages) > 4 {
				m.goBack()
			}
			if active := m.activePage(); active.title != "MAPPINGS" || active.cursor != tc.relation {
				t.Fatalf("back lost mapping selection: %+v", active)
			}
			m.goBack()
			m.goBack()
			if active := m.activePage(); active.title != "TECHNIQUES" || active.cursor != 2 {
				t.Fatalf("back lost original technique selection: %+v", active)
			}
		})
	}
}

func TestTechniqueMappingsKeepEmptyViewsAndWarningNavigation(t *testing.T) {
	m := loadedTestModel()
	for _, relation := range m.relationItems(techniqueItems([]attack.Technique{{ID: "T2000"}})[0]) {
		if relation.count != 0 {
			t.Fatalf("unrelated technique has mappings: %+v", relation)
		}
		m.pushRelation(relation)
		if !strings.Contains(m.contextContent(), "Nothing is available") {
			t.Fatal("empty view not reported")
		}
		m.goBack()
	}
	m.cache.Analytics[0].DataComponents = []string{"unavailable-component"}
	m.pushList("TECHNIQUES", techniqueItems([]attack.Technique{m.cache.Techniques[2]}))
	m.selectCurrent()
	m.selectCurrent()
	m.activePage().cursor = 4
	m.selectCurrent()
	m.selectCurrent()
	if !strings.Contains(m.contextContent(), "UNRESOLVED REFERENCES") {
		t.Fatal("detection reached from a technique lost reference warnings")
	}
}
