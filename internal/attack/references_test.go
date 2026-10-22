package attack

import (
	"reflect"
	"strings"
	"testing"
)

func TestReferenceIssuesSeparateMissingTargetsFromEmptyMappings(t *testing.T) {
	cache := CacheData{
		DataComponents: []DataComponent{{ID: "DC0001", StixID: "component-ref", Name: "Available"}},
		Analytics: []Analytic{
			{ID: "AN0001", StixID: "analytic-ref", DataComponents: []string{"DC0001", "component-ref", "missing-component", "missing-component", "", " "}},
			{ID: "AN0002"},
			{ID: "AN0003", DataComponents: []string{"standalone-missing"}},
		},
		DetectionStrategies: []DetectionStrategy{
			{ID: "DET0001", StixID: "detection-ref", Analytics: []string{"AN0001", "analytic-ref", "missing-analytic", "missing-analytic", "", " "}},
			{ID: "DET0002"},
		},
	}
	componentIssue := ReferenceIssue{"AN0001", "data_component", "missing-component"}
	analyticIssue := ReferenceIssue{"DET0001", "analytic", "missing-analytic"}
	for _, tc := range []struct {
		name string
		got  []ReferenceIssue
		want []ReferenceIssue
	}{
		{"analytic STIX lookup", AnalyticReferenceIssues(cache, "analytic-ref"), []ReferenceIssue{componentIssue}},
		{"detection STIX lookup and inherited components", DetectionReferenceIssues(cache, "detection-ref"), []ReferenceIssue{componentIssue, analyticIssue}},
		{"cache includes unlinked analytics", CacheReferenceIssues(cache), []ReferenceIssue{componentIssue, {"AN0003", "data_component", "standalone-missing"}, analyticIssue}},
		{"empty analytic", AnalyticReferenceIssues(cache, "AN0002"), nil},
		{"empty detection", DetectionReferenceIssues(cache, "DET0002"), nil},
		{"missing analytic", AnalyticReferenceIssues(cache, "not-found"), nil},
		{"missing detection", DetectionReferenceIssues(cache, "not-found"), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !reflect.DeepEqual(tc.got, tc.want) {
				t.Fatalf("issues = %+v; want %+v", tc.got, tc.want)
			}
		})
	}
	if got := DataComponentsByDetectionStrategy(cache, "DET0001"); len(got) != 1 || got[0].ID != "DC0001" {
		t.Fatalf("available results lost or duplicated: %+v", got)
	}
	if got := componentIssue.String(); !strings.Contains(got, "AN0001 -> data component missing-component") || !strings.Contains(got, "unavailable in this matrix cache") {
		t.Fatalf("unhelpful diagnostic: %s", got)
	}
}

func TestReferenceIssueSTIXOnlySourceIDs(t *testing.T) {
	cache := CacheData{
		DetectionStrategies: []DetectionStrategy{{StixID: "detection-only", Analytics: []string{"analytic-only", "missing-analytic"}}},
		Analytics:           []Analytic{{StixID: "analytic-only", DataComponents: []string{"missing-component"}}},
	}
	want := []ReferenceIssue{{"analytic-only", "data_component", "missing-component"}, {"detection-only", "analytic", "missing-analytic"}}
	if got := DetectionReferenceIssues(cache, "detection-only"); !reflect.DeepEqual(got, want) {
		t.Fatalf("STIX-only diagnostics = %+v; want %+v", got, want)
	}
}

func TestSTIXKeepsUnresolvedComponentReferences(t *testing.T) {
	cache, err := BuildCacheDataFromSTIX("testdata/reference-gaps.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(cache.Analytics) != 1 || len(cache.Analytics[0].DataComponents) != 2 {
		t.Fatalf("normalization discarded references: %+v", cache.Analytics)
	}
	want := []ReferenceIssue{{"AN0001", "data_component", "x-mitre-data-component--missing"}}
	if got := DetectionReferenceIssues(cache, "DET0001"); !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized reference issues = %+v; want %+v", got, want)
	}
	if got := DataComponentsByAnalytic(cache, "AN0001"); len(got) != 1 || got[0].ID != "DC0001" {
		t.Fatalf("partial mapping lost available target: %+v", got)
	}
}
