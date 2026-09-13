package attack

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCacheAndMetadataRoundTrip(t *testing.T) {
	// Include each entity and relationship to protect the existing cache schema.
	want := CacheData{
		Techniques:          []Technique{{ID: "T1059", Name: "Interpreter", Tactics: []string{"execution"}, Platforms: []string{"Linux"}, DataSources: []string{"Process"}, DetectionNotes: "Notes", DataComponents: []string{"Process Creation"}}},
		Groups:              []Group{{ID: "G0020", Name: "Group", Aliases: []string{"Alias"}}},
		Mitigations:         []Mitigation{{ID: "M0001", Name: "Mitigation"}},
		Softwares:           []Software{{ID: "S0002", Name: "Software", Type: "malware"}},
		Campaigns:           []Campaign{{ID: "C0001", Name: "Campaign"}},
		Relationships:       []Relationship{{Type: "uses", SourceType: "group", SourceID: "G0020", TargetType: "technique", TargetID: "T1059"}},
		DataComponents:      []DataComponent{{ID: "DC0001", StixID: "component-ref", Name: "Process Creation"}},
		DetectionStrategies: []DetectionStrategy{{ID: "DET0001", StixID: "detection-ref", Analytics: []string{"analytic-ref"}}},
		Analytics:           []Analytic{{ID: "AN0001", StixID: "analytic-ref", DataComponents: []string{"DC0001"}}},
	}
	path := filepath.Join(t.TempDir(), "nested", "cache.json")
	if err := SaveCacheData(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadCacheData(path)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("cache round trip = %+v, %v; want %+v", got, err, want)
	}
	metaPath := filepath.Join(filepath.Dir(path), "meta.json")
	wantMeta := UpdateMeta{ETag: `"dataset"`, LastModified: "Mon, 01 Jun 2026 00:00:00 GMT"}
	if err := SaveUpdateMeta(metaPath, wantMeta); err != nil {
		t.Fatal(err)
	}
	gotMeta, err := LoadUpdateMeta(metaPath)
	if err != nil || gotMeta != wantMeta {
		t.Fatalf("metadata round trip = %+v, %v; want %+v", gotMeta, err, wantMeta)
	}
}

func TestLoadExistingCacheSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	fixture := `{"techniques":[{"id":"T1059","name":"Interpreter","description":"Description","tactics":["execution"],"platforms":["Linux"],"data_sources":["Process"],"detection_notes":"Notes","data_components":["Process Creation"]}],"groups":[],"mitigations":[],"softwares":[],"campaigns":[],"relationships":[],"data_components":[{"id":"DC0001","stix_id":"component-ref","name":"Process Creation","description":"Component"}],"detection_strategies":[{"id":"DET0001","stix_id":"detection-ref","name":"Detection","description":"Strategy","analytics":["analytic-ref"]}],"analytics":[{"id":"AN0001","stix_id":"analytic-ref","name":"Analytic","description":"Logic","data_components":["DC0001"]}]}`
	if err := os.WriteFile(path, []byte(fixture), 0o644); err != nil {
		t.Fatal(err)
	}
	cache, err := LoadCacheData(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cache.Techniques) != 1 || cache.Techniques[0].DetectionNotes != "Notes" || cache.Techniques[0].DataSources[0] != "Process" || cache.DataComponents[0].StixID != "component-ref" || cache.DetectionStrategies[0].Analytics[0] != "analytic-ref" || cache.Analytics[0].DataComponents[0] != "DC0001" {
		t.Fatalf("existing cache fields were lost: %+v", cache)
	}
}

func TestLoadStorageErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	if _, err := LoadCacheData(path); !os.IsNotExist(err) {
		t.Fatalf("cache error = %v; want missing file", err)
	}
	if _, err := LoadUpdateMeta(path); !os.IsNotExist(err) {
		t.Fatalf("metadata error = %v; want missing file", err)
	}
	if err := os.WriteFile(path, []byte("invalid JSON"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCacheData(path); err == nil {
		t.Fatal("invalid cache accepted")
	}
	if _, err := LoadUpdateMeta(path); err == nil {
		t.Fatal("invalid metadata accepted")
	}
}

func TestAtomicWriteFailurePreservesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	if err := os.WriteFile(path, []byte("existing cache"), 0o644); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("write failed")
	err := writeFileAtomic(path, func(file *os.File) error {
		if _, err := file.WriteString("incomplete cache"); err != nil {
			return err
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("write error = %v; want %v", err, wantErr)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "existing cache" {
		t.Fatalf("existing cache replaced: %q, %v", got, err)
	}
	if entries, err := os.ReadDir(filepath.Dir(path)); err != nil || len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v, %v", entries, err)
	}
}
