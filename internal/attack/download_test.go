package attack

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDownloadFileConditional(t *testing.T) {
	previous := UpdateMeta{ETag: `"old"`, LastModified: "Mon, 01 Jun 2026 00:00:00 GMT"}
	for _, tc := range []struct {
		name        string
		force       bool
		status      int
		etag        string
		lastMod     string
		body        string
		truncated   bool
		wantErr     bool
		wantChanged bool
	}{
		{name: "new dataset", status: http.StatusOK, etag: `"new"`, lastMod: "Tue, 02 Jun 2026 00:00:00 GMT", body: "new dataset", wantChanged: true},
		{name: "unchanged dataset", status: http.StatusNotModified},
		{name: "force bypasses validators", force: true, status: http.StatusOK, body: "forced dataset", wantChanged: true},
		{name: "new response without validators clears stale metadata", status: http.StatusOK, body: "new dataset", wantChanged: true},
		{name: "HTTP error preserves existing file", status: http.StatusNotFound, body: "not found", wantErr: true},
		{name: "incomplete response preserves existing file", status: http.StatusOK, body: "partial", truncated: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				wantETag, wantLastMod := previous.ETag, previous.LastModified
				if tc.force {
					wantETag, wantLastMod = "", ""
				}
				if r.Method != http.MethodGet || r.Header.Get("If-None-Match") != wantETag || r.Header.Get("If-Modified-Since") != wantLastMod {
					t.Errorf("unexpected method or conditional headers: %s %v", r.Method, r.Header)
				}
				w.Header().Set("ETag", tc.etag)
				w.Header().Set("Last-Modified", tc.lastMod)
				if tc.truncated {
					w.Header().Set("Content-Length", "100")
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			path := filepath.Join(t.TempDir(), "dataset.json")
			if err := os.WriteFile(path, []byte("existing dataset"), 0o644); err != nil {
				t.Fatal(err)
			}

			result, err := DownloadFileConditional(server.URL, path, previous, tc.force)
			if (err != nil) != tc.wantErr {
				t.Fatalf("download error = %v; wantErr %v", err, tc.wantErr)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			wantBody := "existing dataset"
			if tc.wantChanged {
				wantBody = tc.body
			}
			if string(got) != wantBody {
				t.Fatalf("file = %q; want %q", got, wantBody)
			}
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil || len(entries) != 1 {
				t.Fatalf("temporary files left behind: %v, %v", entries, err)
			}
			if tc.wantErr {
				if result.Downloaded {
					t.Fatal("failed download reported success")
				}
				return
			}
			if result.Downloaded != tc.wantChanged || result.NotModified != (tc.status == http.StatusNotModified) {
				t.Fatalf("unexpected download result: %+v", result)
			}
			wantETag, wantLastMod := tc.etag, tc.lastMod
			if tc.status == http.StatusNotModified {
				wantETag, wantLastMod = previous.ETag, previous.LastModified
			} else if result.Bytes != int64(len(tc.body)) {
				t.Fatalf("bytes = %d; want %d", result.Bytes, len(tc.body))
			}
			if result.ETag != wantETag || result.LastModified != wantLastMod {
				t.Fatalf("unexpected response validators: %+v", result)
			}
		})
	}
}

func TestDownloadCreatesDestinationDirectory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "dataset")
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "nested", "matrix", "dataset.json")
	if _, err := DownloadFileConditional(server.URL, path, UpdateMeta{}, false); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "dataset" {
		t.Fatalf("file = %q, %v", got, err)
	}
}
