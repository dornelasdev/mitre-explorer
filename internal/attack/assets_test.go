package attack

import (
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

func TestICSAssetsNormalizeAndRoundTrip(t *testing.T) {
	cache, err := BuildCacheDataFromSTIX("testdata/ics-assets.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(cache.Assets) != 3 || len(cache.Relationships) != 6 {
		t.Fatalf("normalized %d assets and %d relationships; want 3 and 6", len(cache.Assets), len(cache.Relationships))
	}
	want := Asset{
		ID: "A0001", StixID: "x-mitre-asset--first", Name: "Example Controller",
		Description: "A representative asset class for inventory.",
		Platforms:   []string{"Embedded", "Linux"},
		Sectors:     []string{"General"},
		RelatedAssets: []RelatedAsset{
			{Name: "Monitoring Workstation", Description: "An inventory example.", Sectors: []string{"Water"}},
			{Name: "Standalone monitor", Description: "An example without a specified sector."},
		},
	}
	for _, input := range []string{" a0001 ", "X-MITRE-ASSET--FIRST", " example controller "} {
		if got, found := FindAsset(cache, input); !found || !reflect.DeepEqual(got, want) {
			t.Fatalf("FindAsset(%q) = %+v, %v", input, got, found)
		}
	}
	for _, input := range []string{" ", "example", "A0004", "A0005", "x-mitre-asset--unidentified", "DC0001"} {
		if _, found := FindAsset(cache, input); found {
			t.Fatalf("unexpected asset match for %q", input)
		}
	}
	index := slices.IndexFunc(cache.Relationships, func(rel Relationship) bool { return rel.StixID == "relationship--annotated" })
	wantRelationship := Relationship{
		Type: "targets", SourceType: "technique", SourceID: "T0001", TargetType: "asset", TargetID: "A0001",
		StixID: "relationship--annotated", Description: "An example ATT&CK mapping.", References: []ExternalReference{{SourceName: "Example reference"}},
	}
	if index < 0 || !reflect.DeepEqual(cache.Relationships[index], wantRelationship) {
		t.Fatal("asset relationship or its metadata was lost")
	}

	path := filepath.Join(t.TempDir(), "ics-cache.json")
	if err := SaveCacheData(path, cache); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCacheData(path)
	if err != nil || !reflect.DeepEqual(loaded, cache) {
		t.Fatalf("asset cache round trip changed the data: %v", err)
	}
}

func TestAssetMappingsOnlyFollowDirectEdges(t *testing.T) {
	cache, err := BuildCacheDataFromSTIX("testdata/ics-assets.json")
	if err != nil {
		t.Fatal(err)
	}
	// Exercise cache queries independently of the parser's endpoint filtering.
	cache.Relationships = append(cache.Relationships,
		Relationship{Type: "targets", SourceType: "technique", SourceID: "t0002", TargetType: "asset", TargetID: "X-MITRE-ASSET--FIRST"},
		Relationship{Type: "targets", SourceType: "technique", SourceID: "T0001", TargetType: "asset", TargetID: "A9999"},
		Relationship{Type: "targets", SourceType: "technique", SourceID: "T9999", TargetType: "asset", TargetID: "A0001"},
		Relationship{Type: "targets", SourceType: "group", SourceID: "T0001", TargetType: "asset", TargetID: "A0003"},
		Relationship{Type: "targets", SourceType: "technique", SourceID: "T0001", TargetType: "group", TargetID: "A0003"},
		Relationship{Type: "uses", SourceType: "technique", SourceID: "T0001", TargetType: "asset", TargetID: "A0003"},
		Relationship{Type: "targets", SourceType: "asset", SourceID: "A0003", TargetType: "technique", TargetID: "T0001"},
	)
	for _, tc := range []struct {
		input string
		want  []string
	}{
		{" a0001 ", []string{"T0001", "T0002"}},
		{"X-MITRE-ASSET--FIRST", []string{"T0001", "T0002"}},
		{"Monitoring Workstation", []string{"T0001"}},
		{"A0003", []string{"T0001.001"}},
		{"A9999", nil},
		{" ", nil},
	} {
		var ids []string
		for _, technique := range TechniquesTargetingAsset(cache, tc.input) {
			ids = append(ids, technique.ID)
		}
		if !slices.Equal(ids, tc.want) {
			t.Errorf("TechniquesTargetingAsset(%q) = %v; want %v", tc.input, ids, tc.want)
		}
	}
	for _, tc := range []struct {
		input string
		want  []string
	}{
		{" t0001 ", []string{"A0001", "A0002"}},
		{"T0001.001", []string{"A0003"}},
		{"T0002", []string{"A0001"}},
		{"T9999", nil},
		{" ", nil},
	} {
		var ids []string
		for _, asset := range AssetsTargetedByTechnique(cache, tc.input) {
			ids = append(ids, asset.ID)
		}
		if !slices.Equal(ids, tc.want) {
			t.Errorf("AssetsTargetedByTechnique(%q) = %v; want %v", tc.input, ids, tc.want)
		}
	}
}
