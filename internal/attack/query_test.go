package attack

import (
	"reflect"
	"testing"
)

func TestNormalizeTactic(t *testing.T) {
	got := normalizeTactic("Command-and-Control")
	want := "command and control"

	if got != want {
		t.Fatalf("normalizeTactic() = %q, want %q", got, want)
	}
}

func TestContainsTacticNormalized(t *testing.T) {
	values := []string{"command-and-control", "Initial Access"}

	if !containsTacticNormalized(values, "Command and Control") {
		t.Fatal("expected tactic match with normalized spacing")
	}

	if containsTacticNormalized(values, "Impact") {
		t.Fatal("did not expect unmatched tactic to return true")
	}
}

func TestSearchTechniquesPrioritizesNameMatches(t *testing.T) {
	techniques := []Technique{
		{ID: "T2000", Name: "Other", Description: "PowerShell appears here"},
		{ID: "T1000", Name: "PowerShell", Description: "Name match"},
	}

	results := SearchTechniques(techniques, "powershell", false, 0)
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}
	if results[0].ID != "T1000" {
		t.Fatalf("first result ID = %q, want T1000", results[0].ID)
	}
}

func TestFindTechniqueByID(t *testing.T) {
	techniques := []Technique{{ID: "T1059", Name: "Command and Scripting Interpreter"}}

	technique, found := FindTechniqueByID(techniques, "t1059")
	if !found {
		t.Fatal("expected technique to be found case-insensitively")
	}
	if technique.Name != "Command and Scripting Interpreter" {
		t.Fatalf("technique.Name = %q", technique.Name)
	}
}

func techniqueIDs(techniques []Technique) []string {
	ids := make([]string, len(techniques))
	for i, technique := range techniques {
		ids[i] = technique.ID
	}
	return ids
}

func TestSearchTechniqueOrderingAndLimits(t *testing.T) {
	techniques := []Technique{
		{ID: "T3000", Name: "Other", Description: "powershell description", DetectionNotes: "PowerShell detection"},
		{ID: "T2000", Name: "PowerShell second"},
		{ID: "T1000", Name: "POWERSHELL first", DetectionNotes: "PowerShell detection"},
	}
	for _, tc := range []struct {
		name  string
		query func() []Technique
		want  []string
	}{
		{"rank and ID", func() []Technique { return SearchTechniques(techniques, "PowerShell", false, 0) }, []string{"T1000", "T2000", "T3000"}},
		{"surrounding whitespace", func() []Technique { return SearchTechniques(techniques, " PowerShell ", false, 0) }, []string{"T1000", "T2000", "T3000"}},
		{"name only", func() []Technique { return SearchTechniques(techniques, "powershell", true, 0) }, []string{"T1000", "T2000"}},
		{"limit after ranking", func() []Technique { return SearchTechniques(techniques, "powershell", false, 1) }, []string{"T1000"}},
		{"missing term", func() []Technique { return SearchTechniques(techniques, "missing", false, 0) }, []string{}},
		{"detection ordering", func() []Technique { return SearchDetectionNotes(techniques, " PowerShell ", 0) }, []string{"T1000", "T3000"}},
		{"detection limit", func() []Technique { return SearchDetectionNotes(techniques, "powershell", 1) }, []string{"T1000"}},
		{"blank detection term", func() []Technique { return SearchDetectionNotes(techniques, " ", 0) }, []string{}},
		{"blank technique term", func() []Technique { return SearchTechniques(techniques, " ", false, 0) }, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := techniqueIDs(tc.query()); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("IDs = %v; want %v", got, tc.want)
			}
		})
	}
	if techniques[0].ID != "T3000" {
		t.Fatal("search mutated the input order")
	}
}

func TestFilterTechniquesCombinesFilters(t *testing.T) {
	cache := CacheData{
		Techniques: []Technique{
			{ID: "T3000", Tactics: []string{"execution"}, Platforms: []string{"Windows"}},
			{ID: "T2000", Tactics: []string{"discovery"}, Platforms: []string{"Linux"}},
			{ID: "T1000", Tactics: []string{"execution"}, Platforms: []string{"Linux"}},
			{ID: "T4000", Tactics: []string{"execution"}, Platforms: []string{"Linux"}, DataComponents: []string{"Process Creation"}},
		},
		DataComponents: []DataComponent{{ID: "DC0001", StixID: "component-ref", Name: "Process Creation"}},
		Relationships: []Relationship{
			{Type: "has_data_component", SourceType: "technique", SourceID: "T3000", TargetType: "data_component", TargetID: "DC0001"},
			{Type: "has_data_component", SourceType: "technique", SourceID: "T2000", TargetType: "data_component", TargetID: "component-ref"},
			{Type: "has_data_component", SourceType: "technique", SourceID: "T1000", TargetType: "data_component", TargetID: "DC0001"},
		},
	}
	for _, tc := range []struct {
		name    string
		filters TechniqueFilters
		want    []string
	}{
		{"unfiltered cache order", TechniqueFilters{}, []string{"T3000", "T2000", "T1000", "T4000"}},
		{"tactic", TechniqueFilters{Tactic: "Execution"}, []string{"T1000", "T3000", "T4000"}},
		{"platform", TechniqueFilters{Platform: "linux"}, []string{"T1000", "T2000", "T4000"}},
		{"component relationships", TechniqueFilters{DataComponent: "process"}, []string{"T1000", "T2000", "T3000"}},
		{"all three", TechniqueFilters{Tactic: "Execution", Platform: "linux", DataComponent: "Process Creation"}, []string{"T1000"}},
		{"empty intersection", TechniqueFilters{Tactic: "discovery", Platform: "Windows", DataComponent: "process"}, []string{}},
		{"missing component stays empty", TechniqueFilters{Tactic: "execution", DataComponent: "missing"}, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := techniqueIDs(FilterTechniques(cache, tc.filters)); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("IDs = %v; want %v", got, tc.want)
			}
		})
	}
	if cache.Techniques[0].ID != "T3000" {
		t.Fatal("filtering mutated the cache order")
	}
}

func TestSearchEntitiesTargetsAndOrdering(t *testing.T) {
	cache := CacheData{
		Techniques:          []Technique{{ID: "T0001", Name: "match"}},
		Groups:              []Group{{ID: "G0001", Name: "Group", Description: "match"}},
		Mitigations:         []Mitigation{{ID: "M0001", Name: "match mitigation"}},
		Softwares:           []Software{{ID: "S0001", Name: "match software"}},
		Campaigns:           []Campaign{{ID: "C0001", Description: "MATCH"}},
		DetectionStrategies: []DetectionStrategy{{ID: "DET0001", Name: "match detection"}},
		Analytics:           []Analytic{{ID: "AN0002", Name: "match"}, {ID: "AN0001", Name: "match"}},
		DataComponents:      []DataComponent{{ID: "DC0001", Name: "match component"}},
	}
	results := SearchEntities(cache, "all", "MaTcH", 0)
	var ids []string
	for _, result := range results {
		ids = append(ids, result.ID)
	}
	want := []string{"AN0001", "AN0002", "C0001", "DC0001", "DET0001", "G0001", "M0001", "S0001"}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("all entity IDs = %v; want %v", ids, want)
	}
	limited := SearchEntities(cache, "analytics", "match", 1)
	if len(limited) != 1 || limited[0].ID != "AN0001" || limited[0].Type != "analytic" {
		t.Fatalf("target/limit not applied: %+v", limited)
	}
	byID := SearchEntities(cache, "groups", "g0001", 0)
	if len(byID) != 1 || byID[0].ID != "G0001" {
		t.Fatalf("ID search failed: %+v", byID)
	}
	if len(SearchEntities(cache, "all", "missing", 0)) != 0 {
		t.Fatal("unmatched search returned entities")
	}
	if got := SearchEntities(cache, "groups", " match ", 0); len(got) != 1 || got[0].ID != "G0001" {
		t.Fatalf("entity search did not trim whitespace: %+v", got)
	}
	if len(SearchEntities(cache, "all", " ", 0)) != 0 {
		t.Fatal("blank entity search returned entities")
	}
}
