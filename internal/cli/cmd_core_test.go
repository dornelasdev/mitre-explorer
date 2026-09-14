package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"mitre-explorer/internal/attack"
)

func TestListCombinesTechniqueFilters(t *testing.T) {
	for _, filters := range [][]string{
		{"--tactic", "execution", "--platform", "Linux", "--data-component", "Process Creation"},
		{"--data-component", "Process Creation", "--platform", "Linux", "--tactic", "execution"},
	} {
		t.Run(strings.Join(filters, " "), func(t *testing.T) {
			t.Parallel()
			var output bytes.Buffer
			app := New(nil, &output)
			app.useColor = false
			dir := t.TempDir()
			app.matrix.CachePath = filepath.Join(dir, "cache.json")
			cache := attack.CacheData{
				Techniques: []attack.Technique{
					{ID: "T1000", Tactics: []string{"execution"}, Platforms: []string{"Linux"}},
					{ID: "T2000", Tactics: []string{"discovery"}, Platforms: []string{"Windows"}},
				},
				DataComponents: []attack.DataComponent{{ID: "DC0001", Name: "Process Creation"}},
				Relationships: []attack.Relationship{
					{Type: "has_data_component", SourceType: "technique", SourceID: "T1000", TargetType: "data_component", TargetID: "DC0001"},
					{Type: "has_data_component", SourceType: "technique", SourceID: "T2000", TargetType: "data_component", TargetID: "DC0001"},
				},
			}
			if err := attack.SaveCacheData(app.matrix.CachePath, cache); err != nil {
				t.Fatal(err)
			}
			if err := app.handleList(append([]string{"list", "techniques"}, filters...)); err != nil {
				t.Fatal(err)
			}
			got := output.String()
			if !strings.Contains(got, "T1000") || strings.Contains(got, "T2000") || !strings.Contains(got, "Showing 1-1 of 1") {
				t.Fatalf("combined list output ignored a filter:\n%s", got)
			}
		})
	}
}
