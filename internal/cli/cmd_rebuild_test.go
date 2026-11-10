package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mitre-explorer/internal/attack"
)

func TestLocalRebuildPreservesRawAndMetadata(t *testing.T) {
	for _, matrix := range []MatrixConfig{enterpriseMatrix, mobileMatrix, icsMatrix} {
		t.Run(matrix.Name, func(t *testing.T) {
			app, output, diagnostics, _ := newMatrixFixtureApp(t, matrix, "")
			app.matrix.SourceURL = "://network-must-not-be-used"
			raw, err := os.ReadFile(filepath.Join("..", "attack", "testdata", "procedure-examples.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(app.matrix.RawPath, raw, 0o644); err != nil {
				t.Fatal(err)
			}
			// Rebuilding is independent of the validators and must not read or fix them.
			meta := []byte("existing metadata left byte-for-byte unchanged")
			if err := os.WriteFile(app.matrix.MetaPath, meta, 0o644); err != nil {
				t.Fatal(err)
			}
			if code := app.Run([]string{"update", "--rebuild"}, "test"); code != 0 || diagnostics.Len() != 0 {
				t.Fatalf("exit %d: %s", code, diagnostics.String())
			}
			if !strings.Contains(output.String(), "No download performed") {
				t.Fatalf("rebuild outcome unclear: %s", output.String())
			}
			for path, want := range map[string][]byte{app.matrix.RawPath: raw, app.matrix.MetaPath: meta} {
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("rebuild changed %s: %v", path, err)
				}
			}
			cache, err := attack.LoadCacheData(app.matrix.CachePath)
			if err != nil {
				t.Fatal(err)
			}
			examples := attack.ProcedureExamplesForTechnique(cache, "T1000")
			if len(examples) != 2 || len(examples[1].References) != 2 {
				t.Fatalf("rebuild did not populate procedures: %+v", examples)
			}
		})
	}
}

func TestLocalRebuildFailuresPreserveCache(t *testing.T) {
	for _, failure := range []string{"missing raw", "invalid raw"} {
		t.Run(failure, func(t *testing.T) {
			app, _, diagnostics, _ := newMatrixFixtureApp(t, enterpriseMatrix, "")
			before, err := os.ReadFile(app.matrix.CachePath)
			if err != nil {
				t.Fatal(err)
			}
			if failure == "invalid raw" {
				if err := os.WriteFile(app.matrix.RawPath, []byte("invalid JSON"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if code := app.Run([]string{"update", "--rebuild"}, "test"); code != 1 {
				t.Fatalf("expected operational failure, got %d", code)
			}
			after, err := os.ReadFile(app.matrix.CachePath)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("failed rebuild damaged cache")
			}
			if failure == "missing raw" && !strings.Contains(diagnostics.String(), "run: go run . update --matrix enterprise") {
				t.Fatal("missing raw recovery command absent")
			}
		})
	}
	for _, flags := range [][]string{{"--rebuild", "-f"}, {"--force", "--rebuild"}, {"--rebuild", "extra"}} {
		app, _, diagnostics := fixtureApp(t, "")
		if code := app.Run(append([]string{"update"}, flags...), "test"); code != 2 || strings.Contains(diagnostics.String(), "load update metadata") {
			t.Fatalf("invalid rebuild flags accepted: %d %s", code, diagnostics.String())
		}
	}
}
