package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"mitre-explorer/internal/attack"
)

func regressionCache(matrix MatrixConfig) attack.CacheData {
	prefix := strings.ToUpper(matrix.Name[:1])
	techniqueID := "T" + map[string]string{"enterprise": "1000", "mobile": "2000", "ics": "3000"}[matrix.Name]
	analyticRef := "x-mitre-analytic--" + matrix.Name
	componentRef := "x-mitre-data-component--" + matrix.Name
	return attack.CacheData{
		Techniques:          []attack.Technique{{ID: techniqueID, Name: matrix.Name + " Needle", Tactics: []string{matrix.TacticOrder[0]}, Platforms: []string{matrix.Name + " Platform"}, DataComponents: []string{"Process Creation"}, DetectionNotes: "needle detection"}},
		Groups:              []attack.Group{{ID: prefix + "G0001", Name: matrix.Name + " Group"}},
		Mitigations:         []attack.Mitigation{{ID: prefix + "M0001", Name: matrix.Name + " Mitigation"}},
		Softwares:           []attack.Software{{ID: prefix + "S0001", Name: matrix.Name + " Software"}},
		Campaigns:           []attack.Campaign{{ID: prefix + "C0001", Name: matrix.Name + " Campaign"}},
		DataComponents:      []attack.DataComponent{{ID: prefix + "DC0001", StixID: componentRef, Name: "Process Creation"}},
		DetectionStrategies: []attack.DetectionStrategy{{ID: prefix + "DET0001", Name: matrix.Name + " Detection", Analytics: []string{analyticRef}}},
		Analytics:           []attack.Analytic{{ID: prefix + "AN0001", StixID: analyticRef, Name: matrix.Name + " Analytic", DataComponents: []string{componentRef}}},
		Relationships: []attack.Relationship{
			{Type: "uses", SourceType: "group", SourceID: prefix + "G0001", TargetType: "technique", TargetID: techniqueID},
			{Type: "mitigates", SourceType: "mitigation", SourceID: prefix + "M0001", TargetType: "technique", TargetID: techniqueID},
			{Type: "uses", SourceType: "software", SourceID: prefix + "S0001", TargetType: "technique", TargetID: techniqueID},
			{Type: "uses", SourceType: "campaign", SourceID: prefix + "C0001", TargetType: "technique", TargetID: techniqueID},
			{Type: "detects", SourceType: "detection_strategy", SourceID: prefix + "DET0001", TargetType: "technique", TargetID: techniqueID},
			{Type: "has_data_component", SourceType: "technique", SourceID: techniqueID, TargetType: "data_component", TargetID: prefix + "DC0001"},
		},
	}
}

func newMatrixFixtureApp(t *testing.T, matrix MatrixConfig, input string) (*App, *bytes.Buffer, *bytes.Buffer, attack.CacheData) {
	t.Helper()
	output, diagnostics := new(bytes.Buffer), new(bytes.Buffer)
	app := NewWithStreams(strings.NewReader(input), output, diagnostics)
	app.matrix = matrix
	app.useColor = false
	dir := t.TempDir()
	app.matrix.RawPath = filepath.Join(dir, "raw.json")
	app.matrix.CachePath = filepath.Join(dir, "cache.json")
	app.matrix.MetaPath = filepath.Join(dir, "meta.json")
	cache := regressionCache(matrix)
	if err := attack.SaveCacheData(app.matrix.CachePath, cache); err != nil {
		t.Fatal(err)
	}
	return app, output, diagnostics, cache
}

func TestRepresentativeCommandsAcrossMatrices(t *testing.T) {
	for _, matrix := range []MatrixConfig{enterpriseMatrix, mobileMatrix, icsMatrix} {
		matrix := matrix
		t.Run(matrix.Name, func(t *testing.T) {
			t.Parallel()
			app, output, diagnostics, cache := newMatrixFixtureApp(t, matrix, strings.Repeat("q\n", 12))
			tID, prefix := cache.Techniques[0].ID, strings.ToUpper(matrix.Name[:1])
			report := filepath.Join(t.TempDir(), matrix.Name+".md")
			commands := [][]string{
				{"status"}, {"search", "needle"}, {"search", "needle", "--in-detection"}, {"search", matrix.Name, "--target", "all"},
				{"show", tID}, {"show", "detection", tID}, {"list", "techniques", "--tactic", matrix.TacticOrder[0], "--platform", matrix.Name + " Platform", "--data-component", "Process Creation"},
				{"list", "groups"}, {"list", "mitigations"}, {"list", "software"}, {"list", "campaigns"}, {"list", "detections"}, {"list", "analytics"}, {"list", "data-components"}, {"list", "tactics"}, {"list", "platforms"},
				{"group", prefix + "G0001", "-t"}, {"mitigation", prefix + "M0001", "-t"}, {"software", prefix + "S0001", "-t"}, {"campaign", prefix + "C0001", "-t"},
				{"detection", prefix + "DET0001", "-t", "-a", "-c"}, {"analytic", prefix + "AN0001", "-c"},
				{"export", "detection-components", "--for", prefix + "DET0001", "--format", "md", "--out", report},
			}
			for _, args := range commands {
				if code := app.Run(args, "test"); code != 0 {
					t.Fatalf("%v exit = %d; %s", args, code, diagnostics.String())
				}
			}
			got := output.String()
			for _, want := range []string{"Matrix: " + matrix.Name, tID, matrix.Name + " Needle", prefix + "G0001", prefix + "DET0001", "Process Creation", "Exported"} {
				if !strings.Contains(got, want) {
					t.Fatalf("combined output missing %q", want)
				}
			}
			data, err := os.ReadFile(report)
			if err != nil || !strings.Contains(string(data), matrix.Name) || !strings.Contains(string(data), "Process Creation") {
				t.Fatalf("report mismatch: %v\n%s", err, data)
			}
		})
	}
}

func TestNormalizedSTIXFixtureThroughCommands(t *testing.T) {
	cache, err := attack.BuildCacheDataFromSTIX(filepath.Join("..", "attack", "testdata", "bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	app, output, diagnostics, _ := newMatrixFixtureApp(t, enterpriseMatrix, strings.Repeat("q\n", 4))
	if err := attack.SaveCacheData(app.matrix.CachePath, cache); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(t.TempDir(), "mapping.csv")
	commands := [][]string{
		{"show", cache.Techniques[0].ID},
		{"group", cache.Groups[0].ID, "-t"},
		{"mitigation", cache.Mitigations[0].ID, "-t"},
		{"software", cache.Softwares[0].ID, "-t"},
		{"campaign", cache.Campaigns[0].ID, "-t"},
		{"detection", cache.DetectionStrategies[0].ID, "-t", "-a", "-c"},
		{"analytic", cache.Analytics[0].ID, "-c"},
		{"export", "group-techniques", "--for", cache.Groups[0].ID, "--out", report},
	}
	for _, args := range commands {
		if code := app.Run(args, "test"); code != 0 {
			t.Fatalf("%v exit = %d; %s", args, code, diagnostics.String())
		}
	}
	got := output.String()
	for _, want := range []string{"Interpreter", "Mapped Techniques", "Analytics", "Data Components", "Exported"} {
		if !strings.Contains(got, want) {
			t.Fatalf("normalized fixture output missing %q", want)
		}
	}
	data, err := os.ReadFile(report)
	if err != nil || !strings.Contains(string(data), cache.Groups[0].ID) || !strings.Contains(string(data), cache.Techniques[0].ID) {
		t.Fatalf("normalized mapping report mismatch: %v\n%s", err, data)
	}
}

func TestPaginationNavigationBoundaries(t *testing.T) {
	rows := make([][]string, 55)
	for i := range rows {
		rows[i] = []string{fmt.Sprintf("row-%02d", i+1)}
	}
	app, output, _, _ := newMatrixFixtureApp(t, enterpriseMatrix, "p\nx\nn\nn\nn\np\nq\n")
	app.printPaginatedTable("Rows", []string{"Name"}, rows, []int{10}, 25)
	got := output.String()
	for _, want := range []string{"Showing 1-25 of 55", "Showing 26-50 of 55", "Showing 51-55 of 55", "Already on first page.", "Already on last page.", "Invalid selection."} {
		if !strings.Contains(got, want) {
			t.Fatalf("pagination missing %q:\n%s", want, got)
		}
	}
	if strings.Count(got, "Showing 26-50 of 55") != 2 {
		t.Fatalf("previous did not return to page 2:\n%s", got)
	}
}

func TestPaginationDefaultsAndEmptyRows(t *testing.T) {
	app, output, _, _ := newMatrixFixtureApp(t, enterpriseMatrix, "q\n")
	rows := make([][]string, 26)
	for i := range rows {
		rows[i] = []string{fmt.Sprint(i)}
	}
	app.printPaginatedTable("Default", []string{"Value"}, rows, []int{5}, 0)
	app.printPaginatedTable("Empty", []string{"Value"}, nil, []int{5}, 25)
	if !strings.Contains(output.String(), "Showing 1-25 of 26") || !strings.Contains(output.String(), "No empty found.") {
		t.Fatalf("default/empty pagination mismatch:\n%s", output.String())
	}
}

func TestParseCommandLine(t *testing.T) {
	for _, tc := range []struct {
		line string
		want []string
	}{
		{`list techniques --data-component "Process Creation"`, []string{"list", "techniques", "--data-component", "Process Creation"}},
		{`group 'Lazarus Group' -t`, []string{"group", "Lazarus Group", "-t"}},
		{`search command\ and\ control`, []string{"search", "command and control"}},
		{`search ""`, []string{"search", ""}},
		{"search\tneedle", []string{"search", "needle"}},
	} {
		got, err := parseCommandLine(tc.line)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("parseCommandLine(%q) = %q, %v; want %q", tc.line, got, err, tc.want)
		}
	}
	for _, input := range []string{`search "unterminated`, `search unfinished\`} {
		if _, err := parseCommandLine(input); err == nil {
			t.Fatalf("invalid manual input accepted: %q", input)
		}
	}
}

func TestManualQuotedArgumentsAndRecovery(t *testing.T) {
	input := "2\nlist techniques --data-component \"Process Creation\"\nq\nsearch \"unterminated\nsearch needle\nback\nq\n"
	app, output, diagnostics, cache := newMatrixFixtureApp(t, enterpriseMatrix, input)
	if code := app.Run(nil, "test"); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(output.String(), cache.Techniques[0].ID) || !strings.Contains(output.String(), "Found 1 technique(s)") || !strings.HasSuffix(output.String(), "Exiting.\n") {
		t.Fatalf("quoted session lost commands:\n%s", output.String())
	}
	if strings.Count(diagnostics.String(), "Error:") != 1 || !strings.Contains(diagnostics.String(), "unterminated quote") {
		t.Fatalf("manual parse error mismatch: %s", diagnostics.String())
	}
}

func runBoundedCLIHelper(t *testing.T, matrix string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGuidedRegressionHelper$")
	cmd.Env = append(os.Environ(), "MITRE_EXPLORER_GUIDED_TEST=all", "MITRE_EXPLORER_GUIDED_MATRIX="+matrix)
	processOutput := cappedBuffer{limit: 128 << 10}
	cmd.Stdout, cmd.Stderr = &processOutput, &processOutput
	if err := cmd.Run(); err != nil {
		t.Fatalf("guided %s failed: %v (context: %v)\n%s", matrix, err, ctx.Err(), processOutput.String())
	}
}

func TestGuidedBranches(t *testing.T) {
	for _, matrix := range []string{"enterprise", "mobile", "ics"} {
		t.Run(matrix, func(t *testing.T) { runBoundedCLIHelper(t, matrix) })
	}
}

func TestGuidedEmptySectionsAndMissingCache(t *testing.T) {
	app, output, _, _ := newMatrixFixtureApp(t, enterpriseMatrix, "1\n2\n3\n4\n5\n6\n7\n8\ninvalid\nq\n")
	if err := attack.SaveCacheData(app.matrix.CachePath, attack.CacheData{}); err != nil {
		t.Fatal(err)
	}
	app.runGuidedExplorer()
	got := output.String()
	for _, item := range []string{"tactics", "groups", "mitigations", "softwares", "campaigns", "data components", "detection strategies", "analytics"} {
		if !strings.Contains(got, "No "+item+" found.") {
			t.Fatalf("empty guided cache did not report %s", item)
		}
	}
	if strings.Count(got, "Invalid selection.") != 1 {
		t.Fatalf("invalid guided menu selection not handled once")
	}

	missing, missingOutput, _, _ := newMatrixFixtureApp(t, mobileMatrix, "1\nq\n")
	if err := os.Remove(missing.matrix.CachePath); err != nil {
		t.Fatal(err)
	}
	if code := missing.Run(nil, "test"); code != 0 {
		t.Fatalf("interactive missing cache exit = %d", code)
	}
	if !strings.Contains(missingOutput.String(), "Cache not found for matrix \"mobile\"") || !strings.HasSuffix(missingOutput.String(), "Exiting.\n") {
		t.Fatalf("interactive mode did not recover from missing cache:\n%s", missingOutput.String())
	}
}

func TestGuidedDataComponentUsesSelectedID(t *testing.T) {
	var output bytes.Buffer
	app := New(strings.NewReader("1\n1\nq\n"), &output)
	app.useColor = false
	cache := attack.CacheData{
		Techniques: []attack.Technique{
			{ID: "T1000", Name: "Exact component"},
			{ID: "T2000", Name: "Overlapping component"},
		},
		DataComponents: []attack.DataComponent{
			{ID: "DC0001", Name: "Process"},
			{ID: "DC0002", Name: "Process Creation"},
		},
		Relationships: []attack.Relationship{
			{Type: "has_data_component", SourceType: "technique", SourceID: "T1000", TargetType: "data_component", TargetID: "DC0001"},
			{Type: "has_data_component", SourceType: "technique", SourceID: "T2000", TargetType: "data_component", TargetID: "DC0002"},
		},
	}

	app.runGuidedDataComponents(cache)
	got := output.String()
	if !strings.Contains(got, "T1000") || strings.Contains(got, "T2000") {
		t.Fatalf("guided component selection used a fuzzy name match:\n%s", got)
	}
}

func TestGuidedRegressionHelper(t *testing.T) {
	mode := os.Getenv("MITRE_EXPLORER_GUIDED_TEST")
	if mode == "" {
		return
	}
	matrix, err := matrixFor(os.Getenv("MITRE_EXPLORER_GUIDED_MATRIX"))
	if err != nil {
		t.Fatal(err)
	}
	for mode, script := range guidedRegressionScripts() {
		runGuidedBranchCheck(t, matrix, mode, script)
	}
}

func guidedRegressionScripts() map[string]string {
	return map[string]string{
		"tactics":     "1\n1\n1\n\nb\nq\nq\n",
		"groups":      "2\n1\n1\n1\nb\nq\nq\n",
		"mitigations": "3\n1\n1\n1\nb\nq\nq\n",
		"software":    "4\n1\n1\n1\nb\nq\nq\n",
		"campaigns":   "5\n1\n1\n1\nb\nq\nq\n",
		"components":  "6\n1\n1\n1\nb\nq\nq\n",
		"detections":  "7\n1\n1\n1\n2\n2\n3\n3\nq\nq\n",
		"analytics":   "8\n1\n1\n1\nb\nq\nq\n",
	}
}

func runGuidedBranchCheck(t *testing.T, matrix MatrixConfig, mode, script string) {
	t.Helper()
	output := cappedBuffer{limit: 128 << 10}
	diagnostics := cappedBuffer{limit: 32 << 10}
	app := NewWithStreams(strings.NewReader(script), &output, &diagnostics)
	app.matrix = matrix
	app.useColor = false
	dir := t.TempDir()
	app.matrix.CachePath = filepath.Join(dir, "cache.json")
	cache := regressionCache(matrix)
	if err := attack.SaveCacheData(app.matrix.CachePath, cache); err != nil {
		t.Fatal(err)
	}
	app.runGuidedExplorer()
	got := output.String()
	expected := map[string]string{"tactics": "Technique Details", "groups": "Group Details", "mitigations": "Mitigation Details", "software": "Software Details", "campaigns": "Campaign Details", "components": "Data Component Details", "detections": "Detection Strategy Details", "analytics": "Analytic Details"}[mode]
	mappedResult := cache.Techniques[0].ID
	if mode == "analytics" {
		mappedResult = "Process Creation"
	}
	if !strings.Contains(got, expected) || !strings.Contains(got, mappedResult) || diagnostics.Len() != 0 {
		t.Fatalf("guided output missing %q or %q", expected, mappedResult)
	}
	wantInvalid := 1
	if mode == "detections" {
		wantInvalid = 3
	}
	if mode != "tactics" && strings.Count(got, "Invalid selection.") != wantInvalid {
		t.Fatalf("viewed mapping option was not hidden for %s", mode)
	}
}

type cappedBuffer struct {
	bytes.Buffer
	limit int
}

func (buffer *cappedBuffer) Write(data []byte) (int, error) {
	written := len(data)
	remaining := buffer.limit - buffer.Len()
	if remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
		}
		_, _ = buffer.Buffer.Write(data)
	}
	return written, nil
}
