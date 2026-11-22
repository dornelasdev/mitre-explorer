package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnalyticDetailsAcrossCLIAndGuidedMode(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		args  []string
	}{
		{"CLI", "", []string{"analytic", "AN0001", "-c"}},
		{"manual", "2\nanalytic AN0001 -c\nback\nq\n", nil},
		{"guided", "8\n1\n1\nq\nq\n", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, output, diagnostics, _ := newMatrixFixtureApp(t, enterpriseMatrix, tc.input)
			data, err := os.ReadFile(filepath.Join("..", "attack", "testdata", "analytic-details.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(app.matrix.RawPath, data, 0o644); err != nil {
				t.Fatal(err)
			}
			if code := app.Run([]string{"update", "--rebuild"}, "test"); code != 0 {
				t.Fatalf("fixture rebuild exit %d: %s", code, diagnostics.String())
			}
			output.Reset()
			if tc.name == "guided" {
				app.runGuidedExplorer()
			} else if code := app.Run(tc.args, "test"); code != 0 {
				t.Fatalf("exit %d: %s", code, diagnostics.String())
			}
			if diagnostics.Len() != 0 {
				t.Fatalf("unexpected diagnostics: %s", diagnostics.String())
			}
			got := output.String()
			for _, want := range []string{
				"Platforms: Linux, Windows", "Log Sources",
				"auditd:SYSCALL | Channel: execve", "auditd:SYSCALL | Channel: socket/connect",
				"linux:syslog", "Remote collector | Channel: network", "Channel: process events",
				"Mutable Elements", "ProcessWhitelist: Known safe processes",
				"\n    Start with five minutes.", "2 resolved (incomplete)",
				"AN0001 -> data component x-mitre-data-component--unavailable",
				"Process Creation", "Network Connection",
			} {
				if !strings.Contains(got, want) {
					t.Fatalf("missing %q:\n%s", want, got)
				}
			}
		})
	}
}

func TestAnalyticDetailsWithoutMetadata(t *testing.T) {
	app, output, diagnostics, _ := newMatrixFixtureApp(t, enterpriseMatrix, "")
	if code := app.Run([]string{"analytic", "EAN0001", "-c"}, "test"); code != 0 || diagnostics.Len() != 0 {
		t.Fatalf("legacy cache exit %d: %s", code, diagnostics.String())
	}
	got := output.String()
	for _, absent := range []string{"Platforms:", "Log Sources", "Mutable Elements"} {
		if strings.Contains(got, absent) {
			t.Fatalf("legacy cache showed empty section %q:\n%s", absent, got)
		}
	}
	if !strings.Contains(got, "Process Creation") {
		t.Fatalf("legacy cache lost its component mapping:\n%s", got)
	}
}
