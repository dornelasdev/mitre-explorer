package cli

import (
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"mitre-explorer/internal/attack"
)

func TestShowTechniqueMappingsAcrossMatrices(t *testing.T) {
	for _, matrix := range []MatrixConfig{enterpriseMatrix, mobileMatrix, icsMatrix} {
		t.Run(matrix.Name, func(t *testing.T) {
			cache := regressionCache(matrix)
			ids := map[string]string{
				"groups": cache.Groups[0].ID, "software": cache.Softwares[0].ID,
				"campaigns": cache.Campaigns[0].ID, "mitigations": cache.Mitigations[0].ID,
				"detections": cache.DetectionStrategies[0].ID,
			}
			for _, target := range []string{"groups", "software", "campaigns", "mitigations", "detections", "all"} {
				t.Run(target, func(t *testing.T) {
					app, output, diagnostics, _ := newMatrixFixtureApp(t, matrix, "")
					if code := app.Run([]string{"show", cache.Techniques[0].ID, "--" + target}, "test"); code != 0 || diagnostics.Len() != 0 {
						t.Fatalf("exit %d: %s", code, diagnostics.String())
					}
					for kind, id := range ids {
						want := target == kind || target == "all"
						if strings.Contains(output.String(), id) != want {
							t.Fatalf("target %s: entity %s presence != %v:\n%s", target, id, want, output.String())
						}
					}
				})
			}
			app, output, diagnostics, _ := newMatrixFixtureApp(t, matrix, "")
			args := []string{"show", cache.Techniques[0].ID, "--detections", "--groups", "--groups"}
			if code := app.Run(args, "test"); code != 0 || diagnostics.Len() != 0 {
				t.Fatalf("combined flags exit %d: %s", code, diagnostics.String())
			}
			if strings.Count(output.String(), "Found 1 mapped item(s)") != 2 || strings.Index(output.String(), ids["groups"]) > strings.Index(output.String(), ids["detections"]) {
				t.Fatalf("combined flags were repeated or reordered:\n%s", output.String())
			}
		})
	}
}

func TestShowCompatibilityAndEmptyMappings(t *testing.T) {
	for _, tc := range []struct {
		name   string
		args   []string
		want   []string
		absent []string
	}{
		{"default", []string{"show", "T1000"}, []string{"ID: T1000", "Tactics:"}, []string{"mapped item(s)", "No groups mapped"}},
		{"detection notes", []string{"show", "detection", "T1000"}, []string{"Detection Notes:"}, []string{"Tactics:", "mapped item(s)"}},
		{"empty mappings", []string{"show", "T1000", "--all"}, []string{"No groups mapped", "No software mapped", "No campaigns mapped", "No mitigations mapped", "No detection strategies mapped"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, output, diagnostics := fixtureApp(t, "")
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
					t.Fatalf("unexpected %q:\n%s", absent, output.String())
				}
			}
		})
	}
}

func TestShowMappingValidationPrecedesCacheLoading(t *testing.T) {
	for _, args := range [][]string{
		{"show", "--groups", "T1000"}, {"show", "T1000", "--group"},
		{"show", "T1000", "--all", "extra"}, {"show", "T1000", "--all=false"},
		{"show", "detection", "T1000", "--groups"}, {"show", "detection", "--all"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			app, _, diagnostics := fixtureApp(t, "")
			app.matrix.CachePath = filepath.Join(t.TempDir(), "absent.json")
			if code := app.Run(args, "test"); code != 2 || strings.Count(diagnostics.String(), "Error:") != 1 || strings.Contains(diagnostics.String(), "load enterprise cache") {
				t.Fatalf("invalid options loaded cache or wrong exit %d: %s", code, diagnostics.String())
			}
		})
	}
}

func TestGuidedTechniqueMappingsAndNavigation(t *testing.T) {
	for _, matrix := range []MatrixConfig{enterpriseMatrix, mobileMatrix, icsMatrix} {
		t.Run(matrix.Name, func(t *testing.T) {
			// Tactic -> technique -> all five mappings -> list -> tactics -> menu -> exit.
			app, output, _, cache := newMatrixFixtureApp(t, matrix, "1\n1\n1\n1\n2\n3\n4\n5\nb\nb\nq\nq\n")
			app.runGuidedExplorer()
			for _, id := range []string{cache.Groups[0].ID, cache.Softwares[0].ID, cache.Campaigns[0].ID, cache.Mitigations[0].ID, cache.DetectionStrategies[0].ID} {
				if !strings.Contains(output.String(), id) {
					t.Fatalf("guided mapping missing %s:\n%s", id, output.String())
				}
			}
			if strings.Count(output.String(), "Technique Details") != 1 || strings.Contains(output.String(), "Invalid selection.") || !strings.Contains(output.String(), "Exiting guided explorer.") {
				t.Fatalf("guided back flow changed:\n%s", output.String())
			}
		})
	}
	for _, tc := range []struct {
		name, input string
		menu        bool
		wantErr     error
	}{
		{"enter", "\n", false, nil}, {"back", "b\n", false, nil}, {"menu", "Q\n", true, nil},
		{"EOF", "", false, io.EOF}, {"invalid then back", "99\nb\n", false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, _, _, cache := newMatrixFixtureApp(t, enterpriseMatrix, tc.input)
			menu, err := app.runGuidedTechnique(cache, cache.Techniques[0])
			if menu != tc.menu || !errors.Is(err, tc.wantErr) {
				t.Fatalf("navigation = %v, %v; want %v, %v", menu, err, tc.menu, tc.wantErr)
			}
		})
	}
}

func TestManualShowTechniqueMappings(t *testing.T) {
	app, output, diagnostics, cache := newMatrixFixtureApp(t, mobileMatrix, "")
	app.reader.Reset(strings.NewReader("2\nshow " + cache.Techniques[0].ID + " --groups --detections\nback\nq\n"))
	if code := app.Run(nil, "test"); code != 0 || diagnostics.Len() != 0 || !strings.Contains(output.String(), cache.Groups[0].ID) || !strings.Contains(output.String(), cache.DetectionStrategies[0].ID) {
		t.Fatalf("manual mapping failed: %s\n%s", output.String(), diagnostics.String())
	}
}

func TestShowDoesNotInheritSubtechniqueMappings(t *testing.T) {
	app, output, diagnostics, cache := newMatrixFixtureApp(t, enterpriseMatrix, "")
	cache.Techniques = append(cache.Techniques, attack.Technique{ID: "T1000.001"})
	for i := range cache.Relationships {
		cache.Relationships[i].TargetID = "T1000.001"
	}
	if err := attack.SaveCacheData(app.matrix.CachePath, cache); err != nil {
		t.Fatal(err)
	}
	if code := app.Run([]string{"show", "T1000", "--all"}, "test"); code != 0 || diagnostics.Len() != 0 || strings.Contains(output.String(), cache.Groups[0].ID) {
		t.Fatalf("parent inherited child mappings: %s\n%s", output.String(), diagnostics.String())
	}
}
