package attack

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBuildCacheDataFromSTIX(t *testing.T) {
	cache, err := BuildCacheDataFromSTIX("testdata/bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	for name, counts := range map[string][2]int{
		"techniques":    {len(cache.Techniques), 2},
		"groups":        {len(cache.Groups), 1},
		"mitigations":   {len(cache.Mitigations), 1},
		"software":      {len(cache.Softwares), 2},
		"campaigns":     {len(cache.Campaigns), 1},
		"components":    {len(cache.DataComponents), 2},
		"detections":    {len(cache.DetectionStrategies), 2},
		"analytics":     {len(cache.Analytics), 1},
		"relationships": {len(cache.Relationships), 10},
	} {
		if counts[0] != counts[1] {
			t.Fatalf("%s count = %d; want %d", name, counts[0], counts[1])
		}
	}
	technique := cache.Techniques[0]
	if technique.ID != "T0001" || !reflect.DeepEqual(technique.Tactics, []string{"execution"}) || !reflect.DeepEqual(technique.Platforms, []string{"Linux"}) {
		t.Fatalf("technique fields changed: %+v", technique)
	}
	wantNotes := "Legacy notes\n\nDetect interpreter\n\nStrategy notes\n\nAnalytic logic\n\nInspect command lines"
	if technique.DetectionNotes != wantNotes {
		t.Fatalf("detection notes = %q; want %q", technique.DetectionNotes, wantNotes)
	}
	if cache.Groups[0].Aliases[0] != "Example alias" || cache.Softwares[0].Type != "malware" || cache.Softwares[1].Type != "tool" {
		t.Fatal("group aliases or software types changed")
	}
	if cache.DataComponents[1].ID != "x-mitre-data-component--fallback" || cache.DetectionStrategies[1].ID != "x-mitre-detection-strategy--fallback" {
		t.Fatal("STIX fallback IDs were lost")
	}
	if !reflect.DeepEqual(cache.Analytics[0].DataComponents, []string{"x-mitre-data-component--fallback"}) {
		t.Fatalf("analytic components not resolved/deduplicated: %+v", cache.Analytics[0])
	}
	if !reflect.DeepEqual(cache.DetectionStrategies[0].Analytics, []string{"x-mitre-analytic--first"}) {
		t.Fatal("detection analytic references changed")
	}
	for _, want := range []Relationship{
		{Type: "uses", SourceType: "group", SourceID: "G0020", TargetType: "technique", TargetID: "T0001"},
		{Type: "mitigates", SourceType: "mitigation", SourceID: "M0001", TargetType: "technique", TargetID: "T0001"},
		{Type: "uses", SourceType: "software", SourceID: "S0002", TargetType: "technique", TargetID: "T0001"},
		{Type: "uses", SourceType: "software", SourceID: "S0003", TargetType: "technique", TargetID: "T0001"},
		{Type: "uses", SourceType: "campaign", SourceID: "C0001", TargetType: "technique", TargetID: "T0001"},
		{Type: "detects", SourceType: "detection_strategy", SourceID: "DET0505", TargetType: "technique", TargetID: "T0001"},
		{Type: "detects", SourceType: "detection_strategy", SourceID: "x-mitre-detection-strategy--fallback", TargetType: "technique", TargetID: "T0002"},
		{Type: "has_data_component", SourceType: "technique", SourceID: "T0001", TargetType: "data_component", TargetID: "DC0001"},
		{Type: "has_data_component", SourceType: "technique", SourceID: "T0001", TargetType: "data_component", TargetID: "x-mitre-data-component--fallback"},
		{Type: "has_data_component", SourceType: "technique", SourceID: "T0002", TargetType: "data_component", TargetID: "DC0001"},
	} {
		matches := 0
		for _, got := range cache.Relationships {
			if got == want {
				matches++
			}
		}
		if matches != 1 {
			t.Fatalf("relationship %+v appears %d times; want 1", want, matches)
		}
	}
	if strings.Contains(cache.Techniques[1].DetectionNotes, "Inspect command lines") {
		t.Fatal("detection enrichment leaked between techniques")
	}
}

func TestBuildCacheDataFromSTIXErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.json")
	if _, err := BuildCacheDataFromSTIX(path); !os.IsNotExist(err) {
		t.Fatalf("parse error = %v; want missing file", err)
	}
	if err := os.WriteFile(path, []byte("invalid JSON"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildCacheDataFromSTIX(path); err == nil {
		t.Fatal("invalid bundle accepted")
	}
}
