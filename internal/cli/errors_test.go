package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mitre-explorer/internal/attack"
)

func TestInvalidCommandsValidateBeforeLoadingCache(t *testing.T) {
	cases := [][]string{
		{"unknown"}, {"--matrix"}, {"--matrix", "unsupported"},
		{"search"}, {"search", "--name-only"}, {"search", ""},
		{"search", "term", "--limit"}, {"search", "term", "--limit", "0"},
		{"search", "term", "--limit", "abc"}, {"search", "term", "--limit", "--name-only"},
		{"search", "term", "--target"}, {"search", "term", "--target", "unknown"},
		{"search", "term", "--target", "groups", "--detailed"},
		{"search", "term", "--typo"},
		{"show"}, {"show", "detection"}, {"show", "--detailed"},
		{"show", "T1000", "extra"}, {"show", "detection", "T1000", "extra"},
		{"list"}, {"list", "unknown"}, {"list", "groups", "--typo"},
		{"list", "techniques", "--tactic"}, {"list", "techniques", "--tactic", "--platform", "Linux"},
		{"list", "techniques", "--platform", ""}, {"list", "techniques", "--data-component"},
		{"status", "extra"}, {"tui", "extra"}, {"help", "unknown"}, {"help", "search", "extra"},
		{"update", "--typo"}, {"update", "-f", "extra"},
		{"export"}, {"export", "techniques"}, {"export", "techniques", "--out", "--format", "md"},
		{"export", "techniques", "--out", "x", "--format", "invalid"},
		{"export", "unknown", "--out", "x"}, {"export", "group-techniques", "--out", "x"},
		{"export", "techniques", "--out", "x", "--for", "G0001"},
	}
	for _, entity := range []string{"group", "mitigation", "software", "campaign", "detection", "analytic"} {
		cases = append(cases, []string{entity}, []string{entity, "--plain"}, []string{entity, "id", "--typo"}, []string{entity, "id", "-d"})
	}
	cases = append(cases, []string{"group", "id", "-a"}, []string{"mitigation", "id", "-c"}, []string{"analytic", "id", "-t"})
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			var output, diagnostics bytes.Buffer
			app := NewWithStreams(nil, &output, &diagnostics)
			app.useColor = false
			app.matrix.CachePath = filepath.Join(t.TempDir(), "missing.json")
			if code := app.Run(args, "test"); code != 2 {
				t.Fatalf("exit = %d, want 2; diagnostics: %s", code, diagnostics.String())
			}
			if strings.Count(diagnostics.String(), "Error:") != 1 || strings.Count(diagnostics.String(), "Use:") != 1 {
				t.Fatalf("error must be reported once with one help hint: %q", diagnostics.String())
			}
			if strings.Contains(diagnostics.String(), "load enterprise cache") || strings.Contains(output.String(), "Error:") {
				t.Fatalf("validation occurred after cache I/O or used stdout: %q, %q", output.String(), diagnostics.String())
			}
		})
	}
}

func fixtureApp(t *testing.T, input string) (*App, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	output, diagnostics := new(bytes.Buffer), new(bytes.Buffer)
	app := NewWithStreams(strings.NewReader(input), output, diagnostics)
	app.useColor = false
	dir := t.TempDir()
	app.matrix.CachePath = filepath.Join(dir, "cache.json")
	app.matrix.MetaPath = filepath.Join(dir, "meta.json")
	cache := attack.CacheData{
		Techniques:          []attack.Technique{{ID: "T1000", Name: "Needle", Tactics: []string{"execution"}}},
		Groups:              []attack.Group{{ID: "G0001", Name: "Group"}},
		Mitigations:         []attack.Mitigation{{ID: "M0001", Name: "Mitigation"}},
		Softwares:           []attack.Software{{ID: "S0001", Name: "Software"}},
		Campaigns:           []attack.Campaign{{ID: "C0001", Name: "Campaign"}},
		DetectionStrategies: []attack.DetectionStrategy{{ID: "DET0001", Name: "Detection"}},
		Analytics:           []attack.Analytic{{ID: "AN0001", Name: "Analytic"}},
	}
	if err := attack.SaveCacheData(app.matrix.CachePath, cache); err != nil {
		t.Fatal(err)
	}
	return app, output, diagnostics
}

func TestCommandSuccessAndEmptyResults(t *testing.T) {
	for _, args := range [][]string{
		{"help"}, {"status"}, {"show", "T1000"}, {"show", "detection", "T1000"},
		{"search", "no-match"}, {"search", "no-match", "--target", "groups"},
		{"list", "techniques", "--tactic", "discovery"},
		{"group", "G0001", "-t", "-d"}, {"mitigation", "M0001", "-t"},
		{"software", "S0001", "-t"}, {"campaign", "C0001", "-t"},
		{"detection", "DET0001", "-t", "-a", "-c"}, {"analytic", "AN0001", "-c"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			app, _, diagnostics := fixtureApp(t, "")
			if code := app.Run(args, "test"); code != 0 || diagnostics.Len() != 0 {
				t.Fatalf("exit = %d; diagnostics: %s", code, diagnostics.String())
			}
		})
	}
}

func TestCommandOperationalFailures(t *testing.T) {
	for _, args := range [][]string{{"show", "T9999"}, {"group", "G9999"}, {"mitigation", "M9999"}, {"software", "S9999"}, {"campaign", "C9999"}, {"detection", "DET9999"}, {"analytic", "AN9999"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			app, _, diagnostics := fixtureApp(t, "")
			if code := app.Run(args, "test"); code != 1 || strings.Count(diagnostics.String(), "Error:") != 1 || strings.Contains(diagnostics.String(), "\n\n") {
				t.Fatalf("exit = %d; diagnostics: %q", code, diagnostics.String())
			}
		})
	}
	for _, args := range [][]string{{"search", "term"}, {"show", "T1000"}, {"list", "groups"}, {"group", "G0001"}, {"export", "techniques", "--out", "x"}} {
		t.Run("missing cache "+args[0], func(t *testing.T) {
			app, _, diagnostics := fixtureApp(t, "")
			if err := os.Remove(app.matrix.CachePath); err != nil {
				t.Fatal(err)
			}
			if code := app.Run(args, "test"); code != 1 || !strings.Contains(diagnostics.String(), "run: go run . update") {
				t.Fatalf("exit = %d; diagnostics: %s", code, diagnostics.String())
			}
		})
	}
}

func TestStatusMissingCacheIsInformational(t *testing.T) {
	app, output, diagnostics := fixtureApp(t, "")
	if err := os.Remove(app.matrix.CachePath); err != nil {
		t.Fatal(err)
	}
	if code := app.Run([]string{"status"}, "test"); code != 0 || diagnostics.Len() != 0 || !strings.Contains(output.String(), "Cache: missing") {
		t.Fatalf("status failed: %d, %s", code, diagnostics.String())
	}
}

func TestMalformedFilesReturnOperationalErrors(t *testing.T) {
	for _, file := range []string{"cache", "metadata"} {
		for _, command := range []string{"status", "export"} {
			t.Run(file+" "+command, func(t *testing.T) {
				app, _, diagnostics := fixtureApp(t, "")
				path := app.matrix.CachePath
				if file == "metadata" {
					path = app.matrix.MetaPath
				}
				if err := os.WriteFile(path, []byte("invalid JSON"), 0o644); err != nil {
					t.Fatal(err)
				}
				args := []string{command}
				if command == "export" {
					args = append(args, "techniques", "--out", filepath.Join(t.TempDir(), "out.csv"))
				}
				if code := app.Run(args, "test"); code != 1 || diagnostics.Len() == 0 {
					t.Fatalf("exit = %d; diagnostics: %s", code, diagnostics.String())
				}
			})
		}
	}
}

func TestManualModeRecoversAfterCommandErrors(t *testing.T) {
	app, output, diagnostics := fixtureApp(t, "2\nunknown\nshow T9999\nhelp\nback\nq\n")
	if code := app.Run(nil, "test"); code != 0 {
		t.Fatalf("manual exit = %d", code)
	}
	if strings.Count(diagnostics.String(), "Error:") != 2 || !strings.Contains(output.String(), "Core commands:") || !strings.HasSuffix(output.String(), "Exiting.\n") {
		t.Fatalf("manual mode did not recover: %s\n%s", output.String(), diagnostics.String())
	}
	if code := app.runCommand([]string{"help"}); code != 0 {
		t.Fatal("previous command error leaked into next command")
	}
}

func TestExportWriteFailureAndSuccess(t *testing.T) {
	app, _, diagnostics := fixtureApp(t, "")
	if code := app.Run([]string{"export", "techniques", "--out", t.TempDir()}, "test"); code != 1 {
		t.Fatalf("write failure exit = %d; %s", code, diagnostics.String())
	}
	diagnostics.Reset()
	out := filepath.Join(t.TempDir(), "report.csv")
	if code := app.Run([]string{"export", "techniques", "--out", out}, "test"); code != 0 {
		t.Fatalf("export exit = %d; %s", code, diagnostics.String())
	}
	data, err := os.ReadFile(out)
	if err != nil || !strings.Contains(string(data), "Needle") {
		t.Fatalf("report: %s, %v", data, err)
	}
}

func TestWrappedUsageErrorClassification(t *testing.T) {
	app := New(nil, nil)
	if code := app.reportError(fmt.Errorf("context: %w", invalidUsage("bad option"))); code != 2 {
		t.Fatalf("wrapped usage exit = %d", code)
	}
}

func TestPlainGlobalErrorPreservesSession(t *testing.T) {
	var output, diagnostics bytes.Buffer
	app := NewWithStreams(nil, &output, &diagnostics)
	if code := app.Run([]string{"--matrix", "invalid", "--plain"}, "test"); code != 2 {
		t.Fatalf("exit = %d", code)
	}
	if !app.useColor || app.matrix.Name != "enterprise" {
		t.Fatal("invalid global options changed session state")
	}
	if strings.Contains(diagnostics.String(), "\033[") {
		t.Fatal("--plain was ignored for a global validation error")
	}
}

func TestUnsupportedExportFormatPreservesDestination(t *testing.T) {
	app := New(nil, nil)
	out := filepath.Join(t.TempDir(), "existing.txt")
	if err := os.WriteFile(out, []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := app.writeExportFile(ExportOptions{Format: "invalid", Out: out}, nil, nil); err == nil {
		t.Fatal("unsupported format accepted")
	}
	data, err := os.ReadFile(out)
	if err != nil || string(data) != "existing" {
		t.Fatalf("existing file changed: %q, %v", data, err)
	}
}

func TestHelpMatchesCommandBehavior(t *testing.T) {
	for _, tc := range []struct {
		target string
		want   []string
	}{
		{"", []string{"Exit codes: 0 success, 1 operation failed, 2 invalid usage"}},
		{"update", []string{"-f, --force", "--plain"}},
		{"search", []string{"--in-detection     Search technique detection notes", "--detailed"}},
		{"show", []string{"show detection <technique_id>", "--matrix <matrix>, --plain"}},
		{"list", []string{"Only techniques accept filters", "data-components"}},
		{"group", []string{"requires -t", "--matrix <matrix>"}},
		{"detection", []string{"--analytics", "--components"}},
		{"analytic", []string{"--components", "--matrix <matrix>"}},
		{"status", []string{"missing cache is reported as status information", "--matrix <matrix>, --plain"}},
		{"export", []string{"Output format (default: csv)", "Required only for mapped relationship targets"}},
		{"tui", []string{"object and relationship navigation", "Search cached ATT&CK objects", "Select an existing matrix cache", "contextual keyboard help"}},
	} {
		name := tc.target
		if name == "" {
			name = "global"
		}
		t.Run(name, func(t *testing.T) {
			var output, diagnostics bytes.Buffer
			app := NewWithStreams(nil, &output, &diagnostics)
			args := []string{"help"}
			if tc.target != "" {
				args = append(args, tc.target)
			}
			if code := app.Run(args, "test"); code != 0 || diagnostics.Len() != 0 {
				t.Fatalf("help exit = %d; diagnostics: %s", code, diagnostics.String())
			}
			for _, want := range tc.want {
				if !strings.Contains(output.String(), want) {
					t.Fatalf("help %q missing %q:\n%s", tc.target, want, output.String())
				}
			}
		})
	}
}
