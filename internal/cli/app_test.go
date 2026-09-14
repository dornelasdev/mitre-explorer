package cli

import (
	"bytes"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"mitre-explorer/internal/attack"
)

func TestAppsKeepStateAndStreamsIndependent(t *testing.T) {
	t.Parallel()
	var firstOutput, secondOutput bytes.Buffer
	first, second := New(nil, &firstOutput), New(nil, &secondOutput)
	first.Run([]string{"help", "--matrix", "mobile", "--plain"}, "first")
	second.Run([]string{"help", "--matrix", "ics"}, "second")
	if first.matrix.Name != "mobile" || first.useColor || second.matrix.Name != "ics" || !second.useColor {
		t.Fatal("matrix or color state leaked across applications")
	}
	if !strings.HasPrefix(firstOutput.String(), "MITRE Explorer first\n") || strings.Contains(firstOutput.String(), "MITRE Explorer second") || !strings.HasPrefix(secondOutput.String(), "MITRE Explorer second\n") {
		t.Fatal("application output leaked across streams")
	}
	third := New(nil, nil)
	if err := third.setActiveMatrix("mobile"); err != nil {
		t.Fatal(err)
	}
	first.matrix.TacticOrder[0] = "Custom"
	if third.matrix.TacticOrder[0] != mobileTacticOrder[0] {
		t.Fatal("applications share mutable tactic-order slices")
	}
}

func TestInvalidGlobalOptionsPreserveSession(t *testing.T) {
	var output bytes.Buffer
	app := New(nil, &output)
	if err := app.setActiveMatrix("mobile"); err != nil {
		t.Fatal(err)
	}
	before := app.matrix
	if _, err := app.applyGlobalOptions([]string{"help", "--plain", "--matrix", "ics", "--matrix", "invalid"}); err == nil {
		t.Fatal("invalid matrix accepted")
	}
	if !reflect.DeepEqual(app.matrix, before) || !app.useColor {
		t.Fatal("rejected options partially changed the session")
	}
}

func TestManualGlobalOptionsPersist(t *testing.T) {
	input := "2\nhelp --matrix mobile --plain\nhelp\nhelp --matrix invalid\nback\nq\n"
	var output bytes.Buffer
	app := New(strings.NewReader(input), &output)
	app.Run(nil, "test")
	if app.matrix.Name != "mobile" || app.useColor {
		t.Fatal("manual commands lost session options")
	}
	got := output.String()
	if !strings.Contains(got, "Matrix: mobile") || !strings.Contains(got, "unsupported matrix") || strings.Contains(got, "\033[") || !strings.HasSuffix(got, "Exiting.\n") {
		t.Fatalf("manual session output did not preserve options:\n%s", got)
	}
}

func TestSharedReaderAcrossManualPaginationAndGuidedMode(t *testing.T) {
	// Supplying the entire script at once forces buffering across mode boundaries.
	input := "2\nlist techniques\nq\nsearch needle --name-only\nback\n1\n1\n1\n1\n\nq\nq\nq\n"
	var output bytes.Buffer
	app := New(strings.NewReader(input), &output)
	app.matrix.CachePath = filepath.Join(t.TempDir(), "cache.json")
	cache := attack.CacheData{Techniques: []attack.Technique{
		{ID: "T2000", Name: "Other", Tactics: []string{"discovery"}},
		{ID: "T1000", Name: "Needle", Tactics: []string{"execution"}},
	}}
	if err := attack.SaveCacheData(app.matrix.CachePath, cache); err != nil {
		t.Fatal(err)
	}
	app.Run([]string{"--plain"}, "test")
	got := output.String()
	if !strings.Contains(got, "Showing 1-2 of 2") || !strings.Contains(got, "Found 1 technique(s)") || strings.Count(got, "Technique Details") != 1 || !strings.Contains(got, "Exiting guided explorer.") || !strings.HasSuffix(got, "Exiting.\n") {
		t.Fatalf("buffered commands were lost across navigation:\n%s", got)
	}
}

func TestUnsupportedMatrixStopsBeforeInteractiveMode(t *testing.T) {
	var output bytes.Buffer
	New(nil, &output).Run([]string{"--plain", "--matrix", "invalid"}, "test")
	got := output.String()
	if !strings.Contains(got, "unsupported matrix") || strings.Contains(got, "Guided Explorer") {
		t.Fatalf("unsupported matrix did not stop startup:\n%s", got)
	}
}

func TestSpinnerStopsBeforeFurtherOutput(t *testing.T) {
	var output bytes.Buffer
	app := New(nil, &output)
	stop := app.startSpinner("Checking")
	stop()
	stop()
	fmt.Fprintln(app.out, "After spinner")
	got := output.String()
	if !strings.Contains(got, "Checking... done\n") || !strings.HasSuffix(got, "After spinner\n") {
		t.Fatalf("spinner shutdown overlapped later output: %q", got)
	}
}
