package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"mitre-explorer/internal/attack"
)

func TestICSAssetCommandsAndGuidedMode(t *testing.T) {
	cache, err := attack.BuildCacheDataFromSTIX(filepath.Join("..", "attack", "testdata", "ics-assets.json"))
	if err != nil {
		t.Fatal(err)
	}
	cache.Techniques[0].Tactics = []string{"execution"}
	for _, tc := range []struct {
		name   string
		args   []string
		input  string
		want   []string
		absent []string
	}{
		{"list", []string{"list", "assets"}, "", []string{"Showing 1-3 of 3", "Example Controller"}, nil},
		{"sector", []string{"list", "assets", "--sector", " general "}, "", []string{"Showing 1-1 of 1", "A0001"}, []string{"A0002", "A0003"}},
		{"platform", []string{"list", "asset", "--platform", "linux"}, "", []string{"Showing 1-1 of 1", "A0001"}, []string{"A0002", "A0003"}},
		{"combined filters", []string{"list", "assets", "--platform", "EMBEDDED", "--sector", "GENERAL"}, "", []string{"Showing 1-1 of 1", "A0001"}, []string{"A0002", "A0003"}},
		{"no filter match", []string{"list", "assets", "--sector", "Water"}, "", []string{"No assets match the selected filters."}, []string{"A0001", "--rebuild"}},
		{"no combined match", []string{"list", "assets", "--sector", "General", "--platform", "Windows"}, "", []string{"No assets match the selected filters."}, []string{"A0001", "--rebuild"}},
		{"search", []string{"search", "inventory", "--target", "asset"}, "", []string{"asset", "A0001", "Found 1 result(s)"}, []string{"A0002"}},
		{"search all", []string{"search", "A0001", "--target", "all"}, "", []string{"A0001", "Example Controller"}, nil},
		{"details only", []string{"asset", "example controller"}, "", []string{"ID: A0001", "Platforms: Embedded, Linux", "Sectors: General", "Mapped techniques: 2", "Related Asset Examples", "Monitoring Workstation (sectors: Water)"}, []string{"T0001"}},
		{"detailed mappings", []string{"asset", "a0001", "-t", "-d"}, "", []string{"Mapped Techniques", "T0001", "T0002", "Tactics: execution"}, []string{"T0001.001"}},
		{"technique assets", []string{"show", "T0001", "--assets"}, "", []string{"Targeted Assets", "Found 2 asset(s)", "A0001", "A0002"}, []string{"A0003"}},
		{"all mappings", []string{"show", "T0001.001", "--all"}, "", []string{"Targeted Assets", "A0003"}, []string{"A0001", "A0002"}},
		{"status", []string{"status"}, "", []string{"Assets: 3"}, nil},
		{"help", []string{"help", "asset"}, "", []string{"--matrix ics", "-t, --techniques", "update --rebuild"}, nil},
		{"manual", nil, "2\nasset A0001 -t\nback\nq\n", []string{"Asset Details", "T0002", "Exiting."}, nil},
		{"manual quoted sector", nil, "2\nlist assets --sector \" GENERAL \"\nq\nq\n", []string{"Showing 1-1 of 1", "A0001", "Exiting."}, []string{"A0002", "A0003"}},
		{"guided assets", nil, "1\n9\n1\n1\nb\nq\nq\nq\n", []string{"[9] Explore Assets", "Asset Details", "Mapped Techniques", "T0002", "Exiting guided explorer."}, []string{"Invalid selection."}},
		{"guided technique", nil, "1\n1\n1\n1\n7\nq\nq\nq\n", []string{"[7] View targeted assets", "Found 2 asset(s)", "A0001"}, []string{"A0003", "Invalid selection."}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, output, diagnostics, _ := newMatrixFixtureApp(t, icsMatrix, tc.input)
			if err := attack.SaveCacheData(app.matrix.CachePath, cache); err != nil {
				t.Fatal(err)
			}
			if code := app.Run(tc.args, "test"); code != 0 || diagnostics.Len() != 0 {
				t.Fatalf("exit %d: %s", code, diagnostics.String())
			}
			got := output.String()
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Errorf("missing %q:\n%s", want, got)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(got, absent) {
					t.Errorf("unexpected %q:\n%s", absent, got)
				}
			}
		})
	}
}

func TestAssetAvailabilityAndValidation(t *testing.T) {
	for _, matrix := range []MatrixConfig{enterpriseMatrix, mobileMatrix, icsMatrix} {
		t.Run(matrix.Name, func(t *testing.T) {
			app, output, diagnostics, cache := newMatrixFixtureApp(t, matrix, "")
			if code := app.Run([]string{"show", cache.Techniques[0].ID, "--all"}, "test"); code != 0 ||
				strings.Contains(output.String(), "Targeted Assets") != (matrix.Name == "ics") {
				t.Fatalf("--all matrix behavior changed: %d\n%s\n%s", code, output.String(), diagnostics.String())
			}
			for _, args := range [][]string{
				{"list", "assets"}, {"search", "monitor", "--target", "assets"}, {"asset", "A0001"}, {"show", cache.Techniques[0].ID, "--assets"},
				{"list", "assets", "--sector", "General"},
			} {
				output.Reset()
				diagnostics.Reset()
				code := app.Run(args, "test")
				if matrix.Name == "ics" {
					wantCode := 0
					if args[0] == "asset" {
						wantCode = 1
					}
					if code != wantCode || !strings.Contains(output.String()+diagnostics.String(), "update --rebuild --matrix ics") {
						t.Errorf("legacy cache %v: %d\n%s\n%s", args, code, output.String(), diagnostics.String())
					}
				} else if code != 2 || !strings.Contains(diagnostics.String(), "--matrix ics") {
					t.Errorf("unsupported matrix accepted %v: %d %s", args, code, diagnostics.String())
				}
			}
		})
	}
	app, _, diagnostics, _ := newMatrixFixtureApp(t, icsMatrix, "")
	app.matrix.CachePath = filepath.Join(t.TempDir(), "missing.json")
	for _, args := range [][]string{
		{"asset", "A0001", "-d"}, {"asset", "A0001", "-a"}, {"asset", "A0001", "--software"},
		{"list", "assets", "--tactic", "execution"}, {"search", "monitor", "--target", "assets", "--detailed"},
		{"list", "assets", "--sector"}, {"list", "assets", "--sector", " "},
		{"list", "assets", "--platform", "--sector", "General"},
		{"list", "assets", "--platform", "Linux", "--platform", "Embedded"},
		{"list", "groups", "--sector", "General"},
	} {
		diagnostics.Reset()
		if code := app.Run(args, "test"); code != 2 || strings.Contains(diagnostics.String(), "load ics cache") {
			t.Errorf("invalid %v reached cache: %d %s", args, code, diagnostics.String())
		}
	}
}
