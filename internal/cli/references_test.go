package cli

import (
	"strings"
	"testing"

	"mitre-explorer/internal/attack"
)

func referenceGapCache() attack.CacheData {
	return attack.CacheData{
		DataComponents: []attack.DataComponent{{ID: "DC0001", Name: "Available Component"}},
		Analytics: []attack.Analytic{
			{ID: "AN0001", DataComponents: []string{"DC0001", "missing-component"}},
			{ID: "AN0002", DataComponents: []string{"missing-component"}},
			{ID: "AN0003"},
		},
		DetectionStrategies: []attack.DetectionStrategy{
			{ID: "DET0001", Analytics: []string{"AN0001", "AN0002", "missing-analytic"}},
			{ID: "DET0002"},
		},
	}
}

func TestMappingCommandsExplainReferenceGaps(t *testing.T) {
	for _, tc := range []struct {
		name   string
		args   []string
		want   []string
		absent []string
	}{
		{"partial analytic", []string{"analytic", "AN0001", "-c"}, []string{"1 resolved (incomplete)", "AN0001 -> data component missing-component", "Available Component"}, []string{"No data components mapped"}},
		{"unresolved analytic", []string{"analytic", "AN0002", "-c"}, []string{"0 resolved (incomplete)", "No data components could be resolved from this cache."}, []string{"No data components mapped"}},
		{"empty analytic", []string{"analytic", "AN0003", "-c"}, []string{"No data components mapped for this analytic."}, []string{"Mapping warning:", "incomplete"}},
		{"detection inherits gaps", []string{"detection", "DET0001", "-a", "-c"}, []string{"2 resolved (incomplete)", "1 resolved (incomplete)", "DET0001 -> analytic missing-analytic", "AN0002 -> data component missing-component", "Available Component"}, nil},
		{"empty detection", []string{"detection", "DET0002", "-a", "-c", "-t"}, []string{"No analytics mapped", "No data components mapped", "No techniques mapped"}, []string{"Mapping warning:"}},
		{"status", []string{"status"}, []string{"Detection References", "Unresolved references: 3", "AN0001 -> data component", "DET0001 -> analytic"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, output, diagnostics, _ := newMatrixFixtureApp(t, icsMatrix, "")
			if err := attack.SaveCacheData(app.matrix.CachePath, referenceGapCache()); err != nil {
				t.Fatal(err)
			}
			if code := app.Run(tc.args, "test"); code != 0 || diagnostics.Len() != 0 {
				t.Fatalf("exit %d: %s", code, diagnostics.String())
			}
			for _, want := range tc.want {
				if !strings.Contains(output.String(), want) {
					t.Fatalf("missing %q:\n%s", want, output.String())
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(output.String(), absent) {
					t.Fatalf("misleading %q:\n%s", absent, output.String())
				}
			}
		})
	}
}

func TestGuidedMappingsExplainReferenceGaps(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		run   func(*App, attack.CacheData)
		want  string
	}{
		{"analytic", "2\n1\nq\n", (*App).runGuidedAnalytics, "No data components could be resolved from this cache."},
		{"detection", "1\n2\n3\nq\n", (*App).runGuidedDetections, "DET0001 -> analytic missing-analytic"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, output, _, _ := newMatrixFixtureApp(t, icsMatrix, tc.input)
			tc.run(app, referenceGapCache())
			if !strings.Contains(output.String(), "Mapping warning:") || !strings.Contains(output.String(), tc.want) {
				t.Fatalf("guided diagnostic missing:\n%s", output.String())
			}
		})
	}
}
