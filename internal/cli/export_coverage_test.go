package cli

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"mitre-explorer/internal/attack"
)

func exportFixture(t *testing.T, name string) attack.CacheData {
	t.Helper()
	cache, err := attack.BuildCacheDataFromSTIX(filepath.Join("..", "attack", "testdata", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return cache
}

func runReportFixture(t *testing.T, matrix MatrixConfig, cache attack.CacheData, format, target, anchor string) string {
	t.Helper()
	app, output, diagnostics, _ := newMatrixFixtureApp(t, matrix, "")
	if err := attack.SaveCacheData(app.matrix.CachePath, cache); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "report."+format)
	args := []string{"export", target, "--out", path, "--format", format}
	if anchor != "" {
		args = append(args, "--for", anchor)
	}
	if code := app.Run(args, "test"); code != 0 || diagnostics.Len() != 0 {
		t.Fatalf("%v exit %d: %s", args, code, diagnostics.String())
	}
	if !strings.Contains(output.String(), "from "+matrix.Name+" matrix") {
		t.Fatalf("report did not identify the selected matrix: %s", output.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func reportCSVRows(t *testing.T, data string) [][]string {
	t.Helper()
	rows, err := csv.NewReader(strings.NewReader(data)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestExportProcedureCitations(t *testing.T) {
	cache := exportFixture(t, "procedure-examples")
	for i := range cache.Relationships {
		if cache.Relationships[i].StixID == "relationship--group-parent" {
			cache.Relationships[i].Description = "Procedure | notes\nSecond line"
		}
	}
	data := runReportFixture(t, enterpriseMatrix, cache, "csv", "technique-procedures", " t1000 ")
	want := [][]string{
		{"Technique ID", "Technique Name", "Source Type", "Source ID", "Source Name", "Relationship STIX ID", "Procedure", "Citation Source", "Citation Description", "Citation URL", "Citation External ID"},
		{"T1000", "Parent", "campaign", "C0001", "Example Campaign", "relationship--campaign-parent", "The campaign implemented the technique without a supplied citation.", "", "", "", ""},
		{"T1000", "Parent", "group", "G0001", "Example Group", "relationship--group-parent", "Procedure | notes\nSecond line", "Example Report", "Example Author. Example Report.", "https://example.invalid/report", "REPORT-1"},
		{"T1000", "Parent", "group", "G0001", "Example Group", "relationship--group-parent", "Procedure | notes\nSecond line", "Offline Reference", "An offline publication with no URL.", "", ""},
	}
	if rows := reportCSVRows(t, data); !reflect.DeepEqual(rows, want) {
		t.Fatalf("procedure rows = %#v; want %#v", rows, want)
	}
	md := runReportFixture(t, enterpriseMatrix, cache, "md", "technique-procedures", "T1000.001")
	for _, field := range []string{"| Matrix | enterprise |", "| Target | technique-procedures |", "T1000.001", "Tool Report", "https://example.invalid/tool"} {
		if !strings.Contains(md, field) {
			t.Errorf("Markdown missing %q:\n%s", field, md)
		}
	}
	if strings.Contains(md, "relationship--group-parent") {
		t.Fatal("sub-technique report inherited parent procedures")
	}
	md = runReportFixture(t, enterpriseMatrix, cache, "md", "technique-procedures", "T1000")
	if strings.Count(md, "Procedure \\| notes Second line") != 2 || !strings.Contains(md, "REPORT-1") {
		t.Fatalf("Markdown table did not preserve both citations:\n%s", md)
	}
}

func TestExportICSAssetsAndMappings(t *testing.T) {
	cache := exportFixture(t, "ics-assets")
	list := reportCSVRows(t, runReportFixture(t, icsMatrix, cache, "csv", "assets", ""))
	if len(list) != 4 || len(list[1]) != 7 || list[1][0] != "A0001" || list[1][3] != "Embedded, Linux" ||
		list[1][4] != "General" || !strings.Contains(list[1][6], "Monitoring Workstation (sectors: Water)") {
		t.Fatalf("asset details or ordering lost: %#v", list)
	}
	md := runReportFixture(t, icsMatrix, cache, "md", "assets", "")
	if !strings.Contains(md, "| Matrix | ics |") || !strings.Contains(md, "Standalone monitor") {
		t.Fatalf("Markdown asset metadata or related examples lost:\n%s", md)
	}
	rows := reportCSVRows(t, runReportFixture(t, icsMatrix, cache, "csv", "asset-techniques", "Example Controller"))
	if len(rows) != 3 || rows[1][0] != "A0001" || rows[1][2] != "T0001" || rows[2][2] != "T0002" {
		t.Fatalf("asset-techniques did not deduplicate and resolve direct mappings: %#v", rows)
	}
	md = runReportFixture(t, icsMatrix, cache, "md", "technique-assets", "t0001.001")
	if !strings.Contains(md, "| T0001.001 | Child technique | A0003 |") || strings.Contains(md, "A0001") {
		t.Fatalf("incorrect technique-assets mappings:\n%s", md)
	}
	summary := runReportFixture(t, icsMatrix, cache, "csv", "summary", "")
	if !strings.Contains(summary, "\nAssets,3\n") {
		t.Fatalf("ICS summary missing asset count:\n%s", summary)
	}
}

func TestExportDirectEntityConnections(t *testing.T) {
	cache := exportFixture(t, "entity-connections")
	cache.Groups[0].Aliases = []string{"Group Alias"}
	for _, tc := range []struct {
		target, anchor, sourceID, sourceName, relatedKind, relatedID, relatedName string
	}{
		{"group-software", "Group Alias", "G0001", "Example Group", "Software", "S0001", "Example Software"},
		{"group-campaigns", "g0001", "G0001", "Example Group", "Campaign", "C0001", "Example Campaign"},
		{"software-groups", "Example Software", "S0001", "Example Software", "Group", "G0001", "Example Group"},
		{"software-campaigns", "s0001", "S0001", "Example Software", "Campaign", "C0001", "Example Campaign"},
		{"campaign-software", "Example Campaign", "C0001", "Example Campaign", "Software", "S0001", "Example Software"},
		{"campaign-groups", "c0001", "C0001", "Example Campaign", "Group", "G0001", "Example Group"},
	} {
		t.Run(tc.target, func(t *testing.T) {
			want := [][]string{{"Source ID", "Source Name", tc.relatedKind + " ID", tc.relatedKind + " Name"},
				{tc.sourceID, tc.sourceName, tc.relatedID, tc.relatedName}}
			data := runReportFixture(t, mobileMatrix, cache, "csv", tc.target, tc.anchor)
			if got := reportCSVRows(t, data); !reflect.DeepEqual(got, want) {
				t.Fatalf("rows = %#v; want %#v", got, want)
			}
			md := runReportFixture(t, mobileMatrix, cache, "md", tc.target, tc.anchor)
			if !strings.Contains(md, "| "+strings.Join(want[1], " | ")+" |") {
				t.Fatalf("Markdown lost the same mapping:\n%s", md)
			}
		})
	}
}

func TestExportCoverageValidationAndEmptyResults(t *testing.T) {
	for _, tc := range []struct {
		matrix  MatrixConfig
		args    []string
		code    int
		want    string
		noCache bool
	}{
		{mobileMatrix, []string{"assets"}, 2, "--matrix ics", true},
		{enterpriseMatrix, []string{"asset-techniques", "--for", "A0001"}, 2, "--matrix ics", true},
		{mobileMatrix, []string{"technique-assets", "--for", "T0001"}, 2, "--matrix ics", true},
		{icsMatrix, []string{"assets", "--for", "A0001"}, 2, "--for is only supported", true},
		{icsMatrix, []string{"technique-assets"}, 2, "--for is required", true},
		{enterpriseMatrix, []string{"technique-procedures"}, 2, "--for is required", true},
		{enterpriseMatrix, []string{"group-campaigns"}, 2, "--for is required", true},
		{icsMatrix, []string{"assets"}, 1, "update --rebuild --matrix ics", false},
		{enterpriseMatrix, []string{"technique-procedures", "--for", "T9999"}, 1, "not found", false},
		{enterpriseMatrix, []string{"group-software", "--for", "G9999"}, 1, "not found", false},
	} {
		app, _, diagnostics, _ := newMatrixFixtureApp(t, tc.matrix, "")
		if tc.noCache {
			app.matrix.CachePath = filepath.Join(t.TempDir(), "missing.json")
		}
		path := filepath.Join(t.TempDir(), "existing.csv")
		if err := os.WriteFile(path, []byte("existing report"), 0o644); err != nil {
			t.Fatal(err)
		}
		args := append([]string{"export"}, tc.args...)
		args = append(args, "--out", path)
		if code := app.Run(args, "test"); code != tc.code || !strings.Contains(diagnostics.String(), tc.want) {
			t.Errorf("%s %v exit %d: %s", tc.matrix.Name, args, code, diagnostics.String())
		}
		if data, err := os.ReadFile(path); err != nil || string(data) != "existing report" {
			t.Fatalf("unsuccessful export changed destination: %q, %v", data, err)
		}
	}
	cache := regressionCache(enterpriseMatrix)
	for target, id := range map[string]string{
		"group-software": cache.Groups[0].ID, "technique-procedures": cache.Techniques[0].ID,
	} {
		data := runReportFixture(t, enterpriseMatrix, cache, "csv", target, id)
		if rows := reportCSVRows(t, data); len(rows) != 1 {
			t.Fatalf("empty %s mapping should produce only headers: %#v", target, rows)
		}
	}
}
