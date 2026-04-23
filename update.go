package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

func downloadFile(url, outputPath string) (int64, error) {
	resp, err := http.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("Unexpected HTTP status: %s", resp.Status)
	}

	if err := os.MkdirAll("data", 0o755); err != nil {
		return 0, err
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	n, err := io.Copy(file, resp.Body)
	if err != nil {
		return 0, err
	}

	return n, nil
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
