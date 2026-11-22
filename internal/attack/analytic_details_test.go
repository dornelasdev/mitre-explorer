package attack

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestAnalyticDetailsNormalizationAndCacheRoundTrip(t *testing.T) {
	cache, err := BuildCacheDataFromSTIX("testdata/analytic-details.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(cache.Analytics) != 2 {
		t.Fatalf("inactive analytics retained or active analytics lost: %+v", cache.Analytics)
	}
	want := Analytic{
		ID: "AN0001", StixID: "x-mitre-analytic--details", Name: "Inspect process activity",
		Description:    "Correlate process events with suspicious network activity.",
		DataComponents: []string{"DC0001", "x-mitre-data-component--fallback", "x-mitre-data-component--unavailable"},
		Platforms:      []string{"Linux", "Windows"},
		LogSources: []AnalyticLogSource{
			{DataComponentRef: "x-mitre-data-component--process", Name: "auditd:SYSCALL", Channel: "execve"},
			{DataComponentRef: "x-mitre-data-component--process", Name: "auditd:SYSCALL", Channel: "socket/connect"},
			{DataComponentRef: "x-mitre-data-component--fallback", Name: "linux:syslog"},
			{DataComponentRef: "x-mitre-data-component--unavailable", Name: "Remote collector", Channel: "network"},
			{Name: "Supplementary source", Channel: "events"},
			{DataComponentRef: "x-mitre-data-component--process", Channel: "process events"},
		},
		MutableElements: []MutableElement{
			{Field: "ProcessWhitelist", Description: "Known safe processes; tune to the local environment."},
			{Field: "TimeWindow", Description: "Time window used for correlation.\nStart with five minutes."},
		},
	}
	if !reflect.DeepEqual(cache.Analytics[0], want) {
		t.Fatalf("analytic details lost or conflated:\ngot  %+v\nwant %+v", cache.Analytics[0], want)
	}
	minimal := cache.Analytics[1]
	if minimal.ID != "AN0002" || len(minimal.DataComponents) != 0 || minimal.Platforms != nil || minimal.LogSources != nil || minimal.MutableElements != nil {
		t.Fatalf("absent details invented or leaked from another analytic: %+v", minimal)
	}
	assertAnalyticDetailsMappings(t, cache, want)
	path := filepath.Join(t.TempDir(), "cache.json")
	if err := SaveCacheData(path, cache); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCacheData(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded, cache) {
		t.Fatal("cache round trip changed analytic details")
	}
	assertAnalyticDetailsMappings(t, loaded, want)
}

func assertAnalyticDetailsMappings(t *testing.T, cache CacheData, want Analytic) {
	t.Helper()
	if got := AnalyticsByDetectionStrategy(cache, "DET0001"); !reflect.DeepEqual(got, []Analytic{want}) {
		t.Fatalf("detection-to-analytic query lost details: %+v", got)
	}
	if got, found := FindAnalytic(cache, want.StixID); !found || !reflect.DeepEqual(got, want) {
		t.Fatalf("analytic lookup lost details: %+v, found %v", got, found)
	}
	components := DataComponentsByAnalytic(cache, want.ID)
	if len(components) != 2 || components[0].ID != "x-mitre-data-component--fallback" || components[1].ID != "DC0001" {
		t.Fatalf("component mapping changed or included unresolved targets: %+v", components)
	}
	issues := []ReferenceIssue{{SourceID: "AN0001", TargetType: "data_component", TargetID: "x-mitre-data-component--unavailable"}}
	if got := AnalyticReferenceIssues(cache, want.ID); !reflect.DeepEqual(got, issues) {
		t.Fatalf("unresolved component diagnostics changed: %+v", got)
	}
	if got := DetectionReferenceIssues(cache, "DET0001"); !reflect.DeepEqual(got, issues) {
		t.Fatalf("strategy lost unresolved component diagnostics: %+v", got)
	}
	if got := TechniquesDetectedByStrategy(cache, "DET0001"); len(got) != 1 || got[0].ID != "T0001" {
		t.Fatalf("existing detected-technique mapping changed: %+v", got)
	}
}

func TestLegacyAnalyticCacheWithoutEnrichment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-cache.json")
	legacy := `{"analytics":[{"id":"AN0001","stix_id":"x-mitre-analytic--legacy","name":"Legacy analytic","description":"Existing logic","data_components":["DC0001"]}],"data_components":[{"id":"DC0001","name":"Process Creation"}],"detection_strategies":[{"id":"DET0001","analytics":["x-mitre-analytic--legacy"]}]}`
	if err := os.WriteFile(path, []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	cache, err := LoadCacheData(path)
	if err != nil {
		t.Fatal(err)
	}
	analytics := AnalyticsByDetectionStrategy(cache, "DET0001")
	if len(analytics) != 1 || analytics[0].Description != "Existing logic" {
		t.Fatalf("legacy analytic mapping or fields lost: %+v", analytics)
	}
	analytic := analytics[0]
	if analytic.Platforms != nil || analytic.LogSources != nil || analytic.MutableElements != nil {
		t.Fatalf("legacy cache fabricated analytic details: %+v", analytic)
	}
	if got := DataComponentsByAnalytic(cache, "AN0001"); len(got) != 1 || got[0].ID != "DC0001" {
		t.Fatalf("legacy component mapping changed: %+v", got)
	}
	if err := SaveCacheData(path, cache); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"platforms", "log_sources", "mutable_elements"} {
		if strings.Contains(string(data), `"`+field+`"`) {
			t.Fatalf("absent optional field %q was written to the legacy cache", field)
		}
	}
}
