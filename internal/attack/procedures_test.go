package attack

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestProcedureNormalizationAndCacheRoundTrip(t *testing.T) {
	cache, err := BuildCacheDataFromSTIX("testdata/procedure-examples.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(cache.Relationships) != 6 {
		t.Fatalf("inactive relationships retained: %+v", cache.Relationships)
	}
	examples := ProcedureExamplesForTechnique(cache, " t1000 ")
	if len(examples) != 2 || examples[0].SourceID != "C0001" || examples[1].SourceID != "G0001" {
		t.Fatalf("wrong procedures or ordering: %+v", examples)
	}
	group := examples[1]
	wantReferences := []ExternalReference{
		{SourceName: "Example Report", Description: "Example Author. Example Report.", URL: "https://example.invalid/report", ExternalID: "REPORT-1"},
		{SourceName: "Offline Reference", Description: "An offline publication with no URL."},
	}
	if group.StixID != "relationship--group-parent" || group.SourceName != "Example Group" || group.TechniqueID != "T1000" || group.Description != "The group implemented the technique. (Citation: Example Report)" || !reflect.DeepEqual(group.References, wantReferences) {
		t.Fatalf("procedure/citation metadata lost: %+v", group)
	}
	if len(examples[0].References) != 0 {
		t.Fatal("a citation was invented for uncited procedure text")
	}
	child := ProcedureExamplesForTechnique(cache, "T1000.001")
	if len(child) != 1 || child[0].SourceType != "software" || child[0].SourceID != "S0001" {
		t.Fatalf("parent/child procedures mixed: %+v", child)
	}
	path := filepath.Join(t.TempDir(), "cache.json")
	if err := SaveCacheData(path, cache); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCacheData(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded, cache) || !reflect.DeepEqual(ProcedureExamplesForTechnique(loaded, "T1000"), examples) {
		t.Fatal("cache storage changed the procedure data")
	}
	group.References[0].URL = "changed"
	if got := ProcedureExamplesForTechnique(cache, "T1000")[1].References[0].URL; got != "https://example.invalid/report" {
		t.Fatal("query reference slice aliases the cache")
	}
}

func TestProcedureIdentityAndFiltering(t *testing.T) {
	base := Relationship{Type: "uses", SourceType: "group", SourceID: "G0001", TargetType: "technique", TargetID: "T1000", Description: "First procedure."}
	first, second, third := base, base, base
	first.StixID = "relationship--first"
	second.StixID = "relationship--second"
	second.References = []ExternalReference{{SourceName: "Separate evidence"}}
	third.Description = "Different procedure from the same source."
	cache := CacheData{
		Techniques:    []Technique{{ID: "T1000"}, {ID: "T1000.001"}, {ID: "T2000"}},
		Groups:        []Group{{ID: "G0001", Name: "Group"}},
		Relationships: []Relationship{second, first, first, third},
	}
	if got := ProcedureExamplesForTechnique(cache, "T1000"); len(got) != 3 {
		t.Fatalf("distinct examples lost or identical STIX relationship repeated: %+v", got)
	}
	for _, input := range []string{"", " ", "missing", "T9999", "T2000", "T1000.001"} {
		if got := ProcedureExamplesForTechnique(cache, input); len(got) != 0 {
			t.Fatalf("%q returned unrelated examples: %+v", input, got)
		}
	}
	for _, tc := range []struct {
		name   string
		change func(*Relationship)
	}{
		{"missing source", func(rel *Relationship) { rel.SourceID = "G9999" }},
		{"empty source", func(rel *Relationship) { rel.SourceID = "" }},
		{"wrong source type", func(rel *Relationship) { rel.SourceType = "mitigation" }},
		{"wrong target type", func(rel *Relationship) { rel.TargetType = "software" }},
		{"wrong relationship", func(rel *Relationship) { rel.Type = "mitigates" }},
		{"child only", func(rel *Relationship) { rel.TargetID = "T1000.001" }},
		{"unknown technique", func(rel *Relationship) { rel.TargetID = "T9999" }},
		{"empty description", func(rel *Relationship) { rel.Description = " \n\t" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rel := base
			tc.change(&rel)
			cache.Relationships = []Relationship{rel}
			wantCount := 0
			if tc.name == "child only" {
				wantCount = 1
			}
			if got := ProcedureExamplesForTechnique(cache, rel.TargetID); len(got) != wantCount {
				t.Fatalf("procedure count = %d; want %d: %+v", len(got), wantCount, got)
			}
			if got := ProcedureExamplesForTechnique(cache, "T1000"); len(got) != 0 {
				t.Fatalf("unrelated procedure included: %+v", got)
			}
		})
	}
}

func TestLegacyRelationshipsStillLoadWithoutProcedureMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old-cache.json")
	data := `{"techniques":[{"id":"T1000"}],"groups":[{"id":"G0001","name":"Group"}],"relationships":[{"type":"uses","source_type":"group","source_id":"G0001","target_type":"technique","target_id":"T1000"}]}`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	cache, err := LoadCacheData(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := GroupsUsingTechnique(cache, "T1000"); len(got) != 1 {
		t.Fatal("old relationship mappings stopped working")
	}
	if examples := ProcedureExamplesForTechnique(cache, "T1000"); len(examples) != 0 {
		t.Fatalf("legacy cache fabricated procedure text: %+v", examples)
	}
}
