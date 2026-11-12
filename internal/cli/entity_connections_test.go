package cli

import (
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"mitre-explorer/internal/attack"
)

func addEntityConnections(cache attack.CacheData) attack.CacheData {
	g, s, c := cache.Groups[0].ID, cache.Softwares[0].ID, cache.Campaigns[0].ID
	cache.Relationships = append(cache.Relationships,
		attack.Relationship{Type: "uses", SourceType: "group", SourceID: g, TargetType: "software", TargetID: s},
		attack.Relationship{Type: "uses", SourceType: "campaign", SourceID: c, TargetType: "software", TargetID: s},
		attack.Relationship{Type: "attributed-to", SourceType: "campaign", SourceID: c, TargetType: "group", TargetID: g},
	)
	return cache
}

func TestEntityConnectionsAcrossMatrices(t *testing.T) {
	for _, matrix := range []MatrixConfig{enterpriseMatrix, mobileMatrix, icsMatrix} {
		t.Run(matrix.Name, func(t *testing.T) {
			cache := addEntityConnections(regressionCache(matrix))
			g, s, c := cache.Groups[0].ID, cache.Softwares[0].ID, cache.Campaigns[0].ID
			for _, tc := range []struct {
				entity, id, flag, want, absent string
			}{
				{"group", g, "--software", s, c}, {"group", g, "--campaigns", c, s},
				{"software", s, "--groups", g, c}, {"software", s, "--campaigns", c, g},
				{"campaign", c, "--software", s, g}, {"campaign", c, "--groups", g, s},
			} {
				t.Run(tc.entity+tc.flag, func(t *testing.T) {
					app, output, diagnostics, _ := newMatrixFixtureApp(t, matrix, "")
					if err := attack.SaveCacheData(app.matrix.CachePath, cache); err != nil {
						t.Fatal(err)
					}
					args := []string{tc.entity, tc.id, tc.flag, tc.flag}
					if code := app.Run(args, "test"); code != 0 || diagnostics.Len() != 0 {
						t.Fatalf("exit %d: %s", code, diagnostics.String())
					}
					got := output.String()
					if !strings.Contains(got, tc.want) || strings.Contains(got, tc.absent) || strings.Count(got, "Found 1 mapped item(s)") != 1 {
						t.Fatalf("wrong or duplicated connection:\n%s", got)
					}
				})
			}
			for _, entity := range []string{"group", "software", "campaign"} {
				t.Run(entity+" combined and default", func(t *testing.T) {
					app, output, diagnostics, _ := newMatrixFixtureApp(t, matrix, "")
					if err := attack.SaveCacheData(app.matrix.CachePath, cache); err != nil {
						t.Fatal(err)
					}
					// Names resolve to canonical IDs before querying the graph.
					args := []string{entity, matrix.Name + " " + strings.ToUpper(entity[:1]) + entity[1:], "-d"}
					for _, choice := range entityConnectionChoices(entity) {
						args = append(args, "--"+choice.target)
					}
					args = append(args, "-t")
					if code := app.Run(args, "test"); code != 0 || diagnostics.Len() != 0 {
						t.Fatalf("combined flags exit %d: %s", code, diagnostics.String())
					}
					for _, want := range []string{g, s, c, cache.Techniques[0].ID, "Mapped Techniques"} {
						if !strings.Contains(output.String(), want) {
							t.Fatalf("combined output missing %s:\n%s", want, output.String())
						}
					}
					output.Reset()
					if code := app.Run(args[:2], "test"); code != 0 || strings.Contains(output.String(), "mapped item(s)") || strings.Contains(output.String(), cache.Techniques[0].ID) {
						t.Fatalf("default details changed: %d\n%s", code, output.String())
					}
				})
			}
		})
	}
}

func TestEntityConnectionValidationBeforeCache(t *testing.T) {
	for _, entity := range []string{"group", "software", "campaign", "mitigation", "detection", "analytic"} {
		for _, flag := range []string{"--groups", "--software", "--campaigns"} {
			allowed := false
			for _, choice := range entityConnectionChoices(entity) {
				allowed = allowed || flag == "--"+choice.target
			}
			if allowed {
				continue
			}
			t.Run(entity+flag, func(t *testing.T) {
				app, _, diagnostics := fixtureApp(t, "")
				app.matrix.CachePath = filepath.Join(t.TempDir(), "missing.json")
				if code := app.Run([]string{entity, "example", flag}, "test"); code != 2 || strings.Count(diagnostics.String(), "Error:") != 1 || strings.Contains(diagnostics.String(), "load enterprise cache") {
					t.Fatalf("unsupported flag reached cache: %d %s", code, diagnostics.String())
				}
			})
		}
	}
	for _, args := range [][]string{
		{"group", "G0001", "--softwares"}, {"software", "S0001", "--group"},
		{"campaign", "C0001", "--groups", "-d"}, {"group", "--software", "G0001"},
	} {
		app, _, diagnostics := fixtureApp(t, "")
		app.matrix.CachePath = filepath.Join(t.TempDir(), "missing.json")
		if code := app.Run(args, "test"); code != 2 || strings.Count(diagnostics.String(), "Error:") != 1 || strings.Contains(diagnostics.String(), "load enterprise cache") {
			t.Fatalf("invalid %v reached cache: %d %s", args, code, diagnostics.String())
		}
	}
}

func TestEntityConnectionHelpAndEmptyResults(t *testing.T) {
	for _, entity := range []string{"group", "software", "campaign"} {
		app, output, diagnostics, cache := newMatrixFixtureApp(t, enterpriseMatrix, "")
		if code := app.Run([]string{"help", entity}, "test"); code != 0 || diagnostics.Len() != 0 {
			t.Fatalf("help exit %d: %s", code, diagnostics.String())
		}
		for _, choice := range entityConnectionChoices(entity) {
			if !strings.Contains(output.String(), "--"+choice.target) {
				t.Fatalf("%s help missing %s", entity, choice.target)
			}
		}
		output.Reset()
		id := map[string]string{"group": cache.Groups[0].ID, "software": cache.Softwares[0].ID, "campaign": cache.Campaigns[0].ID}[entity]
		args := []string{entity, id}
		for _, choice := range entityConnectionChoices(entity) {
			args = append(args, "--"+choice.target)
		}
		if code := app.Run(args, "test"); code != 0 || diagnostics.Len() != 0 || strings.Count(output.String(), "No ") != 2 || strings.Contains(output.String(), "mapped item(s)") {
			t.Fatalf("shared techniques fabricated connections: %d\n%s\n%s", code, output.String(), diagnostics.String())
		}
	}
}

func TestGuidedEntityConnectionsAcrossMatrices(t *testing.T) {
	for _, matrix := range []MatrixConfig{enterpriseMatrix, mobileMatrix, icsMatrix} {
		for _, branch := range []string{"2", "4", "5"} {
			t.Run(matrix.Name+branch, func(t *testing.T) {
				// View both connections and techniques, reject a hidden choice, then back out.
				app, output, _, cache := newMatrixFixtureApp(t, matrix, branch+"\n1\n2\n3\n1\n1\nb\nq\nq\n")
				cache = addEntityConnections(cache)
				if err := attack.SaveCacheData(app.matrix.CachePath, cache); err != nil {
					t.Fatal(err)
				}
				app.runGuidedExplorer()
				for _, id := range []string{cache.Groups[0].ID, cache.Softwares[0].ID, cache.Campaigns[0].ID, cache.Techniques[0].ID} {
					if !strings.Contains(output.String(), id) {
						t.Fatalf("guided mapping missing %s:\n%s", id, output.String())
					}
				}
				if strings.Count(output.String(), "Invalid selection.") != 1 || !strings.Contains(output.String(), "Exiting guided explorer.") || strings.Count(output.String(), "[2] View ") != 1 {
					t.Fatalf("guided navigation or hidden choices broke:\n%s", output.String())
				}
			})
		}
	}
}

func TestGuidedEntityMappingExitAndManualConnections(t *testing.T) {
	for _, input := range []string{"b\n", "Q\n", ""} {
		app, _, _, cache := newMatrixFixtureApp(t, enterpriseMatrix, input)
		menu, err := app.runGuidedEntityMappings(cache, "group", cache.Groups[0].ID, cache.Techniques)
		var wantErr error
		if input == "" {
			wantErr = io.EOF
		}
		if menu != (input == "Q\n") || !errors.Is(err, wantErr) {
			t.Fatalf("input %q returned %v, %v", input, menu, err)
		}
	}
	app, output, diagnostics, cache := newMatrixFixtureApp(t, mobileMatrix, "")
	cache = addEntityConnections(cache)
	if err := attack.SaveCacheData(app.matrix.CachePath, cache); err != nil {
		t.Fatal(err)
	}
	app.reader.Reset(strings.NewReader("2\ngroup " + cache.Groups[0].ID + " --software --campaigns\nback\nq\n"))
	if code := app.Run(nil, "test"); code != 0 || diagnostics.Len() != 0 || !strings.Contains(output.String(), cache.Softwares[0].ID) || !strings.Contains(output.String(), cache.Campaigns[0].ID) {
		t.Fatalf("manual connections failed: %d\n%s\n%s", code, output.String(), diagnostics.String())
	}
}
