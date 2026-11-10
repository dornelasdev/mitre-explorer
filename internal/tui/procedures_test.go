package tui

import (
	"path/filepath"
	"strings"
	"testing"

	"mitre-explorer/internal/attack"
)

func TestProcedurePagesCitationsScrollAndBack(t *testing.T) {
	cache, err := attack.BuildCacheDataFromSTIX(filepath.Join("..", "attack", "testdata", "procedure-examples.json"))
	if err != nil {
		t.Fatal(err)
	}
	m := newModel(testOptions("cache.json"))
	updated, _ := m.Update(cacheLoadedMsg{cache: cache})
	m = updated.(model)
	m.width, m.height = 60, 18
	m.pushList("TECHNIQUES", techniqueItems(cache.Techniques))
	m.selectCurrent()
	m.selectCurrent()
	m.activePage().cursor = 5
	m.selectCurrent()
	if active := m.activePage(); active.title != "PROCEDURE EXAMPLES" || len(active.items) != 2 {
		t.Fatalf("wrong procedure list: %+v", active)
	}
	m.activePage().cursor = 1
	m.selectCurrent()
	for _, want := range []string{"PROCEDURE EXAMPLE DETAILS", "Example Group", "(Citation: Example Report)", "Example Author. Example Report.", "https://example.invalid/report", "REPORT-1", "Offline Reference"} {
		if !strings.Contains(m.contextContent(), want) {
			t.Fatalf("procedure detail missing %q:\n%s", want, m.contextContent())
		}
	}
	depth := len(m.pages)
	m.selectCurrent()
	if len(m.pages) != depth {
		t.Fatal("procedure detail unexpectedly opened another mapping")
	}
	maxOffset := m.detailMaxOffset(*m.activePage())
	if maxOffset < 1 {
		t.Fatal("long procedure citations do not scroll")
	}
	m.moveCursor(10000)
	if m.activePage().offset != maxOffset || !strings.Contains(m.View().Content, "Offline Reference") {
		t.Fatal("citation scroll did not reach the last reference")
	}
	m.goBack()
	if m.activePage().cursor != 1 {
		t.Fatal("back lost selected procedure")
	}
	m.activePage().cursor = 0
	m.selectCurrent()
	if !strings.Contains(m.contextContent(), "No citation metadata supplied.") {
		t.Fatal("uncited example fabricated metadata")
	}
	m.goBack()
	m.goBack()
	if m.activePage().title != "MAPPINGS" || m.activePage().cursor != 5 {
		t.Fatal("back lost procedure mapping choice")
	}
}

func TestDistinctProceduresFromSameSourceRemainSelectable(t *testing.T) {
	examples := []attack.ProcedureExample{
		{StixID: "first", SourceID: "G0001", SourceName: "Same Group", Description: "First example"},
		{StixID: "second", SourceID: "G0001", SourceName: "Same Group", Description: "Second example"},
	}
	m := loadedTestModel()
	m.pushList("PROCEDURES", procedureItems(examples))
	for index, example := range examples {
		m.activePage().cursor = index
		m.selectCurrent()
		if !strings.Contains(m.contextContent(), example.Description) || !strings.Contains(m.contextContent(), "Relationship: "+example.StixID) {
			t.Fatal("distinct procedure was lost")
		}
		m.goBack()
	}
}
