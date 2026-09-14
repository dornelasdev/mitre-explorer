package cli

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mitre-explorer/internal/attack"
)

func TestUpdateCommandFailures(t *testing.T) {
	for _, failure := range []string{"metadata read", "HTTP", "parse", "cache write", "metadata write"} {
		t.Run(failure, func(t *testing.T) {
			var output, diagnostics bytes.Buffer
			app := NewWithStreams(nil, &output, &diagnostics)
			app.useColor = false
			dir := t.TempDir()
			app.matrix.RawPath = filepath.Join(dir, "raw.json")
			app.matrix.CachePath = filepath.Join(dir, "cache.json")
			app.matrix.MetaPath = filepath.Join(dir, "meta.json")
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if failure == "HTTP" {
					http.Error(w, "unavailable", http.StatusServiceUnavailable)
					return
				}
				if failure == "parse" {
					_, _ = w.Write([]byte("invalid JSON"))
					return
				}
				// Empty but valid STIX bundle; tests never download production data.
				_, _ = w.Write([]byte(`{"type":"bundle","objects":[]}`))
				if failure == "metadata write" {
					// Turn the metadata destination into a directory after it was read.
					if err := os.Mkdir(app.matrix.MetaPath, 0o755); err != nil {
						t.Error(err)
					}
				}
			}))
			defer server.Close()
			app.matrix.SourceURL = server.URL
			if failure == "metadata read" {
				if err := os.WriteFile(app.matrix.MetaPath, []byte("invalid JSON"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if failure == "cache write" {
				if err := os.Mkdir(app.matrix.CachePath, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if code := app.Run([]string{"update"}, "test"); code != 1 || strings.Count(diagnostics.String(), "Error:") != 1 || strings.Contains(output.String(), "Update complete.") {
				t.Fatalf("exit = %d; stdout: %s; stderr: %s", code, output.String(), diagnostics.String())
			}
			if failure == "metadata read" && requests != 0 {
				t.Fatal("download started before metadata validation")
			}
			if failure == "metadata write" {
				if !strings.Contains(diagnostics.String(), "cache updated") {
					t.Fatal("partial update not explained")
				}
				if _, err := os.Stat(app.matrix.CachePath); err != nil {
					t.Fatalf("cache not saved: %v", err)
				}
			}
		})
	}
}

func TestUnchangedUpdateRebuildsInvalidCache(t *testing.T) {
	var output, diagnostics bytes.Buffer
	app := NewWithStreams(nil, &output, &diagnostics)
	app.useColor = false
	dir := t.TempDir()
	app.matrix.RawPath = filepath.Join(dir, "raw.json")
	app.matrix.CachePath = filepath.Join(dir, "cache.json")
	app.matrix.MetaPath = filepath.Join(dir, "meta.json")

	raw := `{"type":"bundle","objects":[]}`
	if err := os.WriteFile(app.matrix.RawPath, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(app.matrix.CachePath, []byte("invalid JSON"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(app.matrix.MetaPath, []byte(`{"etag":"\"same\""}`), 0o644); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != `"same"` {
			t.Errorf("If-None-Match = %q", r.Header.Get("If-None-Match"))
		}
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()
	app.matrix.SourceURL = server.URL

	if code := app.Run([]string{"update"}, "test"); code != 0 || diagnostics.Len() != 0 {
		t.Fatalf("exit = %d; stdout: %s; stderr: %s", code, output.String(), diagnostics.String())
	}
	if !strings.Contains(output.String(), "Cache file is unreadable or invalid") || !strings.Contains(output.String(), "Update complete.") {
		t.Fatalf("invalid cache was not rebuilt: %s", output.String())
	}
	if _, err := attack.LoadCacheData(app.matrix.CachePath); err != nil {
		t.Fatalf("rebuilt cache is invalid: %v", err)
	}
}
