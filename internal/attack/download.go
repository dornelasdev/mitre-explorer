package attack

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// DownloadResult describes a successful download or an unchanged remote dataset.
type DownloadResult struct {
	Downloaded   bool
	NotModified  bool
	Bytes        int64
	ETag         string
	LastModified string
}

// DownloadFileConditional checks remote validators unless force is set. A new
// response replaces outputPath only after its body is completely written.
func DownloadFileConditional(url, outputPath string, prev UpdateMeta, force bool) (DownloadResult, error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	return downloadFileConditional(client, url, outputPath, prev, force)
}

func downloadFileConditional(client *http.Client, url, outputPath string, prev UpdateMeta, force bool) (DownloadResult, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return DownloadResult{}, err
	}

	if !force {
		if prev.ETag != "" {
			req.Header.Set("If-None-Match", prev.ETag)
		}
		if prev.LastModified != "" {
			req.Header.Set("If-Modified-Since", prev.LastModified)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return DownloadResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return DownloadResult{
			NotModified:  true,
			ETag:         prev.ETag,
			LastModified: prev.LastModified,
		}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return DownloadResult{}, fmt.Errorf("unexpected HTTP status: %s", resp.Status)
	}

	var n int64
	err = writeFileAtomic(outputPath, func(file *os.File) error {
		var copyErr error
		n, copyErr = io.Copy(file, resp.Body)
		return copyErr
	})
	if err != nil {
		return DownloadResult{}, err
	}

	return DownloadResult{
		Downloaded:   true,
		Bytes:        n,
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
	}, nil
}
