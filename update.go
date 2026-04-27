package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

type DownloadResult struct {
	Downloaded bool
	NotModified bool
	Bytes int64
	ETag string
	LastModified string
}

func downloadFileConditional(url, outputPath string, prev UpdateMeta, force bool) (DownloadResult, error) {
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

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return DownloadResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return DownloadResult{
			NotModified: true,
			ETag: prev.ETag,
			LastModified: prev.LastModified,
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return DownloadResult{}, fmt.Errorf("Unexpected HTTP status: %s", resp.Status)
	}

	if err := os.MkdirAll("data", 0o755); err != nil {
		return DownloadResult{}, err
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return DownloadResult{}, err
	}
	defer file.Close()

	n, err := io.Copy(file, resp.Body)
	if err != nil {
		return DownloadResult{}, err
	}

	etag := resp.Header.Get("ETag")
	if etag == "" {
		etag = prev.ETag
	}

	lastMod := resp.Header.Get("Last-Modified")
	if lastMod == "" {
		lastMod = prev.LastModified
	}

	return DownloadResult{
		Downloaded: true,
		Bytes: n,
		ETag: etag,
		LastModified: lastMod,
	}  , nil
}

func buildTechniquesFromSTIX(path string) ([]Technique, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var bundle STIXBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, err
	}

	var techniques []Technique

	for _, obj := range bundle.Objects {
		if obj.Type != "attack-pattern" {
			continue
		}

		id := ""
		for _, ref := range obj.ExternalReferences {
			if ref.SourceName == "mitre-attack" && ref.ExternalID != "" {
				id = ref.ExternalID
				break
			}
		}
		if id == "" {
			continue
		}

		var tactics []string
		for _, phase := range obj.KillChainPhases {
			if phase.PhaseName != "" {
				tactics = append(tactics, phase.PhaseName)
			}
		}

		techniques = append(techniques, Technique{
			ID: id,
			Name: obj.Name,
			Description: obj.Description,
			Tactics: tactics,
			Platforms: obj.XMitrePlatforms,
			DataSources: obj.XMitreDataSources,
			DetectionNotes: obj.XMitreDetection,
		})
	}

	return techniques, nil
}

func saveTechniques(path string, techniques []Technique) error {
	data, err := json.MarshalIndent(techniques, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll("data", 0o755); err != nil {
		return err
	}

	return os.WriteFile(path, data, 0o644)
}

func loadTechniques(path string) ([]Technique, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var techniques []Technique
	if err := json.Unmarshal(data, &techniques); err != nil {
		return nil, err
	}

	return techniques, nil
}

func loadUpdateMeta(path string) (UpdateMeta, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return UpdateMeta{}, err
	}

	var m UpdateMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return UpdateMeta{}, err
	}
	return m, nil
}

func saveUpdateMeta(path string, m UpdateMeta) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll("data", 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
