package cli

import (
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"mitre-explorer/internal/attack"
)

func procedureFixture(t *testing.T) attack.CacheData {
	t.Helper()
	cache, err := attack.BuildCacheDataFromSTIX(filepath.Join("..", "attack", "testdata", "procedure-examples.json"))
	if err != nil {
		t.Fatal(err)
	}
	return cache
}

func TestShowProcedureExamplesAcrossMatrices(t *testing.T) {
	for _, matrix := range []MatrixConfig{enterpriseMatrix, mobileMatrix, icsMatrix} {
		for _, flags := range [][]string{{"--procedures"}, {"--procedures", "--procedures"}, {"--all"}} {
			t.Run(matrix.Name+strings.Join(flags, " "), func(t *testing.T) {
				app, output, diagnostics, _ := newMatrixFixtureApp(t, matrix, "")
				if err := attack.SaveCacheData(app.matrix.CachePath, procedureFixture(t)); err != nil {
					t.Fatal(err)
				}
				if code := app.Run(append([]string{"show", "T1000"}, flags...), "test"); code != 0 || diagnostics.Len() != 0 {
					t.Fatalf("exit %d: %s", code, diagnostics.String())
				}
				for _, want := range []string{"Found 2 procedure example(s)", "Example Group", "relationship--group-parent", "(Citation: Example Report)", "Example Author. Example Report.", "URL: https://example.invalid/report", "External ID: REPORT-1", "Offline Reference", "No citation metadata supplied."} {
					if !strings.Contains(output.String(), want) {
						t.Fatalf("missing %q:\n%s", want, output.String())
					}
				}
				if strings.Count(output.String(), "Found 2 procedure example(s)") != 1 || strings.Contains(output.String(), "tool implemented the sub-technique") {
					t.Fatalf("repeated or inherited procedures:\n%s", output.String())
				}
			})
		}
	}
}

func TestProcedureFlagsAndLegacyCache(t *testing.T) {
	for _, args := range [][]string{{"show", "T1000", "--procedure"}, {"show", "detection", "T1000", "--procedures"}, {"show", "--procedures", "T1000"}} {
		app, _, diagnostics := fixtureApp(t, "")
		app.matrix.CachePath = filepath.Join(t.TempDir(), "absent")
		if code := app.Run(args, "test"); code != 2 || strings.Contains(diagnostics.String(), "load enterprise cache") {
			t.Fatalf("validation failed: %d %s", code, diagnostics.String())
		}
	}
	app, output, diagnostics := fixtureApp(t, "")
	if code := app.Run([]string{"show", "T1000", "--procedures"}, "test"); code != 0 || diagnostics.Len() != 0 || !strings.Contains(output.String(), "No procedure examples found") {
		t.Fatalf("old/empty cache failed: %s %s", output.String(), diagnostics.String())
	}
}

func TestGuidedProcedureSelectionAndBackNavigation(t *testing.T) {
	cache := procedureFixture(t)
	// Option 6 opens procedures, 2 selects the cited group example, then return
	// through procedures and technique mappings to the technique list.
	app, output, _, _ := newMatrixFixtureApp(t, enterpriseMatrix, "6\n2\n\nb\nb\n")
	menu, err := app.runGuidedTechnique(cache, cache.Techniques[0])
	if err != nil || menu || strings.Count(output.String(), "Technique Details") != 1 || !strings.Contains(output.String(), "https://example.invalid/report") || strings.Contains(output.String(), "Invalid selection.") {
		t.Fatalf("guided flow = %v, %v:\n%s", menu, err, output.String())
	}
	examples := attack.ProcedureExamplesForTechnique(cache, "T1000")
	for _, tc := range []struct {
		name, input string
		menu        bool
		err         error
	}{
		{"EOF at list", "", false, io.EOF}, {"EOF at detail", "1\n", false, io.EOF},
		{"quit list", "Q\n", true, nil}, {"quit detail", "2\nq\n", true, nil},
		{"back", "b\n", false, nil}, {"invalid selections", "99\n2\ninvalid\nb\nb\n", false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, _, _, _ := newMatrixFixtureApp(t, enterpriseMatrix, tc.input)
			menu, err := app.runGuidedProcedures(examples)
			if menu != tc.menu || !errors.Is(err, tc.err) {
				t.Fatalf("got %v, %v; want %v, %v", menu, err, tc.menu, tc.err)
			}
		})
	}
	app, emptyOutput, _, _ := newMatrixFixtureApp(t, enterpriseMatrix, "")
	if menu, err := app.runGuidedProcedures(nil); menu || err != nil || !strings.Contains(emptyOutput.String(), "No procedure examples found") {
		t.Fatal("empty procedures read input or lost empty message")
	}
}

func TestManualModeProcedureCommand(t *testing.T) {
	app, output, diagnostics, _ := newMatrixFixtureApp(t, mobileMatrix, "2\nshow T1000 --procedures\nback\nq\n")
	if err := attack.SaveCacheData(app.matrix.CachePath, procedureFixture(t)); err != nil {
		t.Fatal(err)
	}
	if code := app.Run(nil, "test"); code != 0 || diagnostics.Len() != 0 || !strings.Contains(output.String(), "URL: https://example.invalid/report") || !strings.HasSuffix(output.String(), "Exiting.\n") {
		t.Fatalf("manual procedure flow: %s\n%s", output.String(), diagnostics.String())
	}
}
