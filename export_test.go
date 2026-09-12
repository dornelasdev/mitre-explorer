package main

import "testing"

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
