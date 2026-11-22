package tui

import (
	"path/filepath"
	"strings"
	"testing"

	"mitre-explorer/internal/attack"

	tea "charm.land/bubbletea/v2"
)

func TestAnalyticDetailsFromDetectionMapping(t *testing.T) {
	cache, err := attack.BuildCacheDataFromSTIX(filepath.Join("..", "attack", "testdata", "analytic-details.json"))
	if err != nil {
		t.Fatal(err)
	}
	m := newModel(testOptions("data/cache.json"))
	loaded, _ := m.Update(cacheLoadedMsg{cache: cache})
	m = loaded.(model)
	m.width, m.height = 70, 20
	m.pushList("DETECTION STRATEGIES", m.itemsForCategory("detections"))
	m.selectCurrent()
	m.selectCurrent()
	if m.activePage().title != "MAPPINGS" {
		t.Fatal("expected detection mapping chooser")
	}
	m.activePage().cursor = 1 // Analytics, after detected techniques.
	m.selectCurrent()
	m.selectCurrent()
	current := m.activePage()
	if current.kind != pageDetail || current.detail.id != "AN0001" {
		t.Fatalf("analytic details not opened: %+v", current)
	}
	detail := m.contextContent()
	for _, want := range []string{
		"Platforms: Linux, Windows", "Log Sources:",
		"auditd:SYSCALL | Channel: execve", "auditd:SYSCALL | Channel: socket/connect",
		"Mutable Elements:", "ProcessWhitelist: Known safe processes",
		"AN0001 -> data component x-mitre-data-component--unavailable",
	} {
		if !strings.Contains(detail, want) {
			t.Fatalf("missing %q:\n%s", want, detail)
		}
	}
	lastLine := "Start with five minutes."
	if strings.Contains(m.View().Content, lastLine) {
		t.Fatal("fixture should require scrolling to see the last mutable element")
	}
	for steps := m.detailMaxOffset(*current); steps > 0; steps-- {
		m, _ = sendKey(m, tea.KeyPressMsg{Code: tea.KeyDown})
	}
	if view := m.View().Content; !strings.Contains(view, lastLine) {
		t.Fatalf("last mutable element unreachable by scrolling:\n%s", view)
	}
	offset := m.activePage().offset
	m.selectCurrent()
	if active := m.activePage(); len(active.items) != 2 || len(active.issues) != 1 {
		t.Fatalf("existing component mapping changed: %+v", active)
	}
	m.goBack()
	if active := m.activePage(); active.detail.id != "AN0001" || active.offset != offset {
		t.Fatalf("back navigation lost analytic scroll position: %+v", active)
	}
}

func TestAnalyticDetailHidesAbsentMetadata(t *testing.T) {
	m := loadedTestModel()
	m.pushList("ANALYTICS", m.itemsForCategory("analytics"))
	m.selectCurrent()
	detail := m.contextContent()
	for _, absent := range []string{"Platforms:", "Log Sources:", "Mutable Elements:"} {
		if strings.Contains(detail, absent) {
			t.Fatalf("legacy cache showed empty section %q:\n%s", absent, detail)
		}
	}
	if !strings.Contains(detail, "Enter: Data Components (1)") {
		t.Fatalf("legacy cache lost its component mapping:\n%s", detail)
	}
}
