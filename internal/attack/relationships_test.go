package attack

import (
	"reflect"
	"testing"
)

func TestTechniqueRelationshipQueries(t *testing.T) {
	for _, tc := range []struct {
		name       string
		query      func(CacheData, string) []Technique
		typeName   string
		sourceType string
		sourceID   string
	}{
		{"group", TechniquesUsedByGroup, "uses", "group", "G0001"},
		{"mitigation", TechniquesMitigatedBy, "mitigates", "mitigation", "M0001"},
		{"software", TechniquesUsedBySoftware, "uses", "software", "S0001"},
		{"campaign", TechniquesUsedByCampaign, "uses", "campaign", "C0001"},
		{"detection", TechniquesDetectedByStrategy, "detects", "detection_strategy", "DET0001"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache := CacheData{Techniques: []Technique{{ID: "T2000"}, {ID: "T1000"}}}
			for _, id := range []string{"T2000", "T1000", "T2000", "T9999"} {
				cache.Relationships = append(cache.Relationships, Relationship{Type: tc.typeName, SourceType: tc.sourceType, SourceID: tc.sourceID, TargetType: "technique", TargetID: id})
			}
			cache.Relationships = append(cache.Relationships,
				Relationship{Type: "wrong", SourceType: tc.sourceType, SourceID: tc.sourceID, TargetType: "technique", TargetID: "T1000"},
				Relationship{Type: tc.typeName, SourceType: "wrong", SourceID: tc.sourceID, TargetType: "technique", TargetID: "T1000"},
				Relationship{Type: tc.typeName, SourceType: tc.sourceType, SourceID: "OTHER", TargetType: "technique", TargetID: "T1000"},
				Relationship{Type: tc.typeName, SourceType: tc.sourceType, SourceID: tc.sourceID, TargetType: "wrong", TargetID: "T1000"},
			)
			if got := techniqueIDs(tc.query(cache, tc.sourceID)); !reflect.DeepEqual(got, []string{"T1000", "T2000"}) {
				t.Fatalf("mapped IDs = %v", got)
			}
			if len(tc.query(cache, "missing")) != 0 {
				t.Fatal("unmatched source returned techniques")
			}
			// Wrong relationship shapes must not produce results on their own.
			cache.Relationships = cache.Relationships[4:]
			if len(tc.query(cache, tc.sourceID)) != 0 {
				t.Fatal("unrelated relationships returned techniques")
			}
		})
	}
}

func TestDataComponentLookupAndLegacyFallback(t *testing.T) {
	cache, err := BuildCacheDataFromSTIX("testdata/bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"process", "PROCESS CREATION", "DC0001", " dc0001 ", "x-mitre-data-component--first"} {
		if got := techniqueIDs(TechniquesByDataComponent(cache, input)); !reflect.DeepEqual(got, []string{"T0001", "T0002"}) {
			t.Fatalf("component %q IDs = %v", input, got)
		}
	}
	legacy := CacheData{Techniques: []Technique{
		{ID: "T2000", DataSources: []string{"Process: Process Creation"}},
		{ID: "T1000", DataComponents: []string{"Process Creation"}},
	}}
	if got := techniqueIDs(TechniquesByDataComponent(legacy, "process creation")); !reflect.DeepEqual(got, []string{"T1000", "T2000"}) {
		t.Fatalf("legacy component IDs = %v", got)
	}
	for _, input := range []string{"", " ", "missing"} {
		if len(TechniquesByDataComponent(cache, input)) != 0 {
			t.Fatalf("component %q returned techniques", input)
		}
	}
}

func TestDetectionAnalyticComponentResolution(t *testing.T) {
	cache := CacheData{
		DetectionStrategies: []DetectionStrategy{{ID: "DET0001", StixID: "detection-ref", Name: "Strategy", Analytics: []string{"AN0003", "AN0002", "AN0001", "analytic-ref", "missing", ""}}},
		Analytics: []Analytic{
			{ID: "AN0003", StixID: "analytic-ref", DataComponents: []string{"DC0002"}},
			{ID: "AN0002", DataComponents: []string{"DC0003", "DC0002", ""}},
			{ID: "AN0001", DataComponents: []string{"component-ref", "DC0001", "missing"}},
		},
		DataComponents: []DataComponent{
			{ID: "DC0003", Name: "Same"},
			{ID: "DC0002", Name: "Same"},
			{ID: "DC0001", StixID: "component-ref", Name: "Alpha"},
		},
	}
	analytics := AnalyticsByDetectionStrategy(cache, "detection-ref")
	var ids []string
	for _, analytic := range analytics {
		ids = append(ids, analytic.ID)
	}
	if !reflect.DeepEqual(ids, []string{"AN0001", "AN0002", "AN0003"}) {
		t.Fatalf("analytics lost or duplicated: %v", ids)
	}
	for _, tc := range []struct {
		name       string
		components []DataComponent
		want       []string
	}{
		{"analytic external/STIX refs", DataComponentsByAnalytic(cache, "an0001"), []string{"DC0001"}},
		{"analytic without STIX IDs", DataComponentsByAnalytic(cache, "AN0002"), []string{"DC0002", "DC0003"}},
		{"strategy union", DataComponentsByDetectionStrategy(cache, "Strategy"), []string{"DC0001", "DC0002", "DC0003"}},
		{"missing analytic", DataComponentsByAnalytic(cache, "missing"), []string{}},
		{"missing strategy", DataComponentsByDetectionStrategy(cache, "missing"), []string{}},
	} {
		ids := make([]string, len(tc.components))
		for i, component := range tc.components {
			ids[i] = component.ID
		}
		if !reflect.DeepEqual(ids, tc.want) {
			t.Fatalf("%s IDs = %v; want %v", tc.name, ids, tc.want)
		}
	}
}
