package attack

import (
	"reflect"
	"testing"
)

func reverseTestIDs[T any](entities []T, id func(T) string) []string {
	var out []string
	for _, entity := range entities {
		out = append(out, id(entity))
	}
	return out
}

func TestReverseTechniqueRelationshipQueries(t *testing.T) {
	for _, tc := range []struct {
		name         string
		relationship string
		sourceType   string
		ids          []string
		query        func(CacheData, string) []string
	}{
		{"groups", "uses", "group", []string{"G0001", "G0002"}, func(cache CacheData, id string) []string {
			return reverseTestIDs(GroupsUsingTechnique(cache, id), func(group Group) string { return group.ID })
		}},
		{"software", "uses", "software", []string{"S0001", "S0002"}, func(cache CacheData, id string) []string {
			return reverseTestIDs(SoftwareUsingTechnique(cache, id), func(software Software) string { return software.ID })
		}},
		{"campaigns", "uses", "campaign", []string{"C0001", "C0002"}, func(cache CacheData, id string) []string {
			return reverseTestIDs(CampaignsUsingTechnique(cache, id), func(campaign Campaign) string { return campaign.ID })
		}},
		{"mitigations", "mitigates", "mitigation", []string{"M0001", "M0002"}, func(cache CacheData, id string) []string {
			return reverseTestIDs(MitigationsForTechnique(cache, id), func(mitigation Mitigation) string { return mitigation.ID })
		}},
		{"detections", "detects", "detection_strategy", []string{"DET0001", "DET0002"}, func(cache CacheData, id string) []string {
			return reverseTestIDs(DetectionStrategiesForTechnique(cache, id), func(detection DetectionStrategy) string { return detection.ID })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache := CacheData{
				Techniques:          []Technique{{ID: "T1059"}, {ID: "T1059.001"}, {ID: "T2000"}},
				Groups:              []Group{{ID: "G0002"}, {ID: "G0001"}, {ID: "G0001"}},
				Softwares:           []Software{{ID: "S0002"}, {ID: "S0001"}, {ID: "S0001"}},
				Campaigns:           []Campaign{{ID: "C0002"}, {ID: "C0001"}, {ID: "C0001"}},
				Mitigations:         []Mitigation{{ID: "M0002"}, {ID: "M0001"}, {ID: "M0001"}},
				DetectionStrategies: []DetectionStrategy{{ID: "DET0002"}, {ID: "DET0001"}, {ID: "DET0001"}},
			}
			edge := func(sourceID, targetID string) Relationship {
				return Relationship{Type: tc.relationship, SourceType: tc.sourceType, SourceID: sourceID, TargetType: "technique", TargetID: targetID}
			}
			cache.Relationships = []Relationship{
				edge(tc.ids[1], "T1059"), edge(tc.ids[0], "T1059"), edge(tc.ids[1], "T1059"),
				edge("MISSING", "T1059"), edge("", "T1059"),
				edge(tc.ids[0], "T1059.001"), edge(tc.ids[0], "T9999"),
				{Type: "wrong", SourceType: tc.sourceType, SourceID: tc.ids[0], TargetType: "technique", TargetID: "T1059"},
				{Type: tc.relationship, SourceType: "wrong", SourceID: tc.ids[0], TargetType: "technique", TargetID: "T1059"},
				{Type: tc.relationship, SourceType: tc.sourceType, SourceID: tc.ids[0], TargetType: "wrong", TargetID: "T1059"},
				{Type: tc.relationship, SourceType: "technique", SourceID: "T1059", TargetType: tc.sourceType, TargetID: tc.ids[0]},
			}
			for _, input := range []string{"T1059", "t1059", " T1059 "} {
				if got := tc.query(cache, input); !reflect.DeepEqual(got, tc.ids) {
					t.Fatalf("query %q = %v; want %v", input, got, tc.ids)
				}
			}
			if got := tc.query(cache, "T1059.001"); !reflect.DeepEqual(got, tc.ids[:1]) {
				t.Fatalf("parent edges leaked into child query: %v", got)
			}
			for _, input := range []string{"", " ", "missing", "T9999", "T2000"} {
				if got := tc.query(cache, input); len(got) != 0 {
					t.Fatalf("query %q returned %v", input, got)
				}
			}
			allRelationships := cache.Relationships
			cache.Relationships = allRelationships[7:]
			if got := tc.query(cache, "T1059"); len(got) != 0 {
				t.Fatalf("unrelated relationship types or directions returned %v", got)
			}
			// With only child edges, a parent query must remain empty.
			cache.Relationships = []Relationship{edge(tc.ids[0], "T1059.001")}
			if got := tc.query(cache, "T1059"); len(got) != 0 {
				t.Fatalf("child edges leaked into parent query: %v", got)
			}
			cache.Relationships = cache.Relationships[:0]
			if got := tc.query(cache, "T1059.001"); len(got) != 0 {
				t.Fatalf("empty mappings returned %v", got)
			}
		})
	}
}

func TestReverseDetectionReferencesAndValuePreservation(t *testing.T) {
	first := DetectionStrategy{ID: "DET0001", StixID: "detection-ref", Name: "First", Description: "Preserved", Analytics: []string{"AN0001"}}
	fallback := DetectionStrategy{StixID: "fallback-ref", Name: "Fallback"}
	second := DetectionStrategy{ID: "DET0002", StixID: "second-ref"}
	cache := CacheData{
		Techniques:          []Technique{{ID: "T1059"}},
		DetectionStrategies: []DetectionStrategy{fallback, second, first},
		Relationships: []Relationship{
			{Type: "detects", SourceType: "detection_strategy", SourceID: "detection-ref", TargetType: "technique", TargetID: "T1059"},
			{Type: "detects", SourceType: "detection_strategy", SourceID: "det0001", TargetType: "technique", TargetID: "t1059"},
			{Type: "detects", SourceType: "detection_strategy", SourceID: "fallback-ref", TargetType: "technique", TargetID: "T1059"},
			{Type: "detects", SourceType: "detection_strategy", SourceID: "DET0002", TargetType: "technique", TargetID: "T1059"},
		},
	}
	if got := DetectionStrategiesForTechnique(cache, "T1059"); !reflect.DeepEqual(got, []DetectionStrategy{first, second, fallback}) {
		t.Fatalf("reverse detections changed values, order, or uniqueness: %+v", got)
	}
	if !reflect.DeepEqual(cache.DetectionStrategies, []DetectionStrategy{fallback, second, first}) {
		t.Fatal("query reordered the cache")
	}
}

func TestReverseMappingsDoNotInferSoftwareUsage(t *testing.T) {
	cache := CacheData{
		Techniques: []Technique{{ID: "T1059"}},
		Groups:     []Group{{ID: "G0001"}},
		Campaigns:  []Campaign{{ID: "C0001"}},
		Softwares:  []Software{{ID: "S0001", Name: "Preserved", Type: "tool", Aliases: []string{"Alias"}}},
		Relationships: []Relationship{
			{Type: "uses", SourceType: "group", SourceID: "G0001", TargetType: "software", TargetID: "S0001"},
			{Type: "uses", SourceType: "campaign", SourceID: "C0001", TargetType: "software", TargetID: "S0001"},
			{Type: "uses", SourceType: "software", SourceID: "S0001", TargetType: "technique", TargetID: "T1059"},
		},
	}
	if len(GroupsUsingTechnique(cache, "T1059")) != 0 || len(CampaignsUsingTechnique(cache, "T1059")) != 0 {
		t.Fatal("software usage was incorrectly treated as a direct technique mapping")
	}
	if got := SoftwareUsingTechnique(cache, "T1059"); !reflect.DeepEqual(got, cache.Softwares) {
		t.Fatalf("software details lost: %+v", got)
	}
}

func TestReverseMappingsFromNormalizedSTIX(t *testing.T) {
	cache, err := BuildCacheDataFromSTIX("testdata/bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := GroupsUsingTechnique(cache, "T0001"); len(got) != 1 || got[0].ID != "G0020" {
		t.Fatalf("normalized group mapping: %+v", got)
	}
	if got := SoftwareUsingTechnique(cache, "T0001"); len(got) != 2 || got[0].ID != "S0002" || got[1].ID != "S0003" {
		t.Fatalf("normalized software mapping: %+v", got)
	}
	if got := CampaignsUsingTechnique(cache, "T0001"); len(got) != 1 || got[0].ID != "C0001" {
		t.Fatalf("normalized campaign mapping: %+v", got)
	}
	if got := MitigationsForTechnique(cache, "T0001"); len(got) != 1 || got[0].ID != "M0001" {
		t.Fatalf("normalized mitigation mapping: %+v", got)
	}
	if got := DetectionStrategiesForTechnique(cache, "T0001"); len(got) != 1 || got[0].ID != "DET0505" {
		t.Fatalf("normalized detection mapping: %+v", got)
	}
	if got := DetectionStrategiesForTechnique(cache, "T0002"); len(got) != 1 || got[0].ID != "x-mitre-detection-strategy--fallback" {
		t.Fatalf("normalized STIX fallback mapping: %+v", got)
	}
}
