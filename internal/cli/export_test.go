package cli

import (
	"strings"
	"testing"
)

func TestMarkdownCellEscapesPipesAndNewlines(t *testing.T) {
	got := markdownCell("hello|world\nnext")
	want := "hello\\|world next"

	if got != want {
		t.Fatalf("markdownCell() = %q, want %q", got, want)
	}
}

func TestParseExportOptions(t *testing.T) {
	opts, err := parseExportOptions([]string{"--format", "md", "--out", "reports/out.md", "--for", "G0020"})
	if err != nil {
		t.Fatalf("parseExportOptions returned error: %v", err)
	}
	if opts.Format != "md" {
		t.Fatalf("Format = %q, want md", opts.Format)
	}
	if opts.Out != "reports/out.md" {
		t.Fatalf("Out = %q", opts.Out)
	}
	if opts.For != "G0020" {
		t.Fatalf("For = %q", opts.For)
	}
}

func TestParseExportOptionsRequiresOut(t *testing.T) {
	if _, err := parseExportOptions([]string{"--format", "csv"}); err == nil {
		t.Fatal("expected missing --out error")
	}
}

func TestReportsUseSessionPaths(t *testing.T) {
	first, second := New(nil, nil), New(nil, nil)
	first.matrix.CachePath, first.matrix.MetaPath = "first/cache.json", "first/meta.json"
	second.matrix.CachePath, second.matrix.MetaPath = "second/cache.json", "second/meta.json"
	for _, app := range []*App{first, second} {
		report := app.markdownReport(ExportOptions{Matrix: app.matrix.Name}, []string{"ID"}, nil)
		if !strings.Contains(report, app.matrix.CachePath) || !strings.Contains(report, app.matrix.MetaPath) {
			t.Fatalf("report used another session's paths:\n%s", report)
		}
	}
}
