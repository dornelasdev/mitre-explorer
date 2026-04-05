package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type Technique struct {
	ID string `json:"id"`
	Name string `json:"name"`
	Description string `json:"description"`
	Tactics []string `json:"tactics"`
	Platforms []string `json:"platforms"`
	DataSources []string `json:"data_sources"`
	DetectionNotes string `json:"detection_notes"`
}

type STIXBundle struct {
	Objects []STIXObject `json:"objects"`
}

type STIXObject struct {
	Type string `json:"type"`
	Name string `json:"name"`
	Description string `json:"description"`

	KillChainPhases []struct {
		PhaseName string `json:"phase_name"`
	} `json:"kill_chain_phases"`

	XMitrePlatforms []string `json:"x_mitre_platforms"`
	XMitreDataSources []string `json:"x_mitre_data_sources"`
	XMitreDetection string `json:"x_mitre_detection"`

	ExternalReferences []struct {
		SourceName string `json:"source_name"`
		ExternalID string `json:"external_id"`
	} `json:"external_references"`
}

const cachePath = "data/mitre-cache.json"

func main() {
	fmt.Println("MITRE Explorer v0.2")

	if len(os.Args) < 2 {
		fmt.Println("Usage: go run . <command>")
		return
	}

	command := os.Args[1]

	switch command {
	case "update":
		const sourceURL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
		const rawPath = "data/enterprise-attack.json"

		force := len(os.Args) >= 3 && os.Args[2] == "-f"

		var n int64
		if !force {
			if info, err := os.Stat(rawPath); err == nil {
				n = info.Size()
				fmt.Printf("Raw file already exists: %s\n", rawPath)
				fmt.Println("Skipping download. Use `go run . update --force` to re-download")
			} else {
				stop := startSpinner("Downloading ATT&CK data")
				n, err = downloadFile(sourceURL, rawPath)
				stop()
				if err != nil {
					fmt.Printf("Update failed: %v\n", err)
					return
				}
			}
		} else {
			stop := startSpinner("Downloading ATT&CK data")
			var err error
			n, err = downloadFile(sourceURL, rawPath)
			stop()
			if err != nil {
				fmt.Printf("Update failed: %v\n", err)
				return
			}
		}

		techniques, err := buildTechniquesFromSTIX(rawPath)
		if err != nil {
			fmt.Printf("Parse failed: %v\n", err)
			return
		}

		if err := saveTechniques(cachePath, techniques); err != nil {
			fmt.Printf("Cache write failed: %v\n", err)
			return
		}

		fmt.Println("Update complete.")
		fmt.Printf("Source: %s\n", sourceURL)
		fmt.Printf("Saved: %s\n", rawPath)
		fmt.Printf("Size: %s (%d bytes)\n", humanSize(n), n)
		fmt.Printf("Cache: %s\n", cachePath)
		fmt.Printf("Parsed techniques: %d\n", len(techniques))

	case "search":
		if len(os.Args) < 3 {
			fmt.Println("Usage: go run . search <term>")
			return
		}
		techniques, err := loadTechniques(cachePath)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Println("Cache not found. Run: go run . update")
				return
			}
			fmt.Printf("Error loading cache: %v\n", err)
			return
		}

		term := os.Args[2]
		results := searchTechniques(techniques, term)

		if len(results) == 0 {
			fmt.Println("No techniques found.")
			return
		}

		fmt.Printf("Found %d technique(s):\n", len(results))
		for _, r := range results {
			fmt.Printf("- %s | %s\n", r.ID, r.Name)
		}

	case "show":
		if len(os.Args) < 3 {
			fmt.Println("Usage: go run . show <technique_id>")
			return
		}
		techniques, err := loadTechniques(cachePath)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Println("Cache not found. Run: go run . update")
				return
			}
			fmt.Printf("Error loading cache: %v\n", err)
			return
		}

		id := os.Args[2]
		technique, found := findTechniqueByID(techniques, id)

		if !found {
			fmt.Printf("Technique %s not found in cache. Try: go run . update\n", id)
			return
		}

		fmt.Printf("ID: %s\n", technique.ID)
		fmt.Printf("Name: %s\n", technique.Name)
		fmt.Printf("Description: %s\n", technique.Description)
		fmt.Printf("Tactics: %s\n", strings.Join(technique.Tactics, ", "))
		fmt.Printf("Platforms: %s\n", strings.Join(technique.Platforms, ", "))
		fmt.Printf("Data Sources: %s\n", strings.Join(technique.DataSources, ", "))
		fmt.Printf("Detection Notes: %s\n", technique.DetectionNotes)

	default:
		fmt.Printf("Unknown command: %s\n", command)
	}
}

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

func containsIgnoreCase(text, term string) bool {
	return strings.Contains(strings.ToLower(text), strings.ToLower(term))
}

func searchTechniques(techniques []Technique, term string) []Technique {
	var results []Technique

	for _, t := range techniques {
		if containsIgnoreCase(t.Name, term) || containsIgnoreCase(t.Description, term) {
			results = append(results, t)
		}
	}

	return results
}

func findTechniqueByID(techniques []Technique, id string) (Technique, bool) {
	for _, t := range techniques {
		if strings.EqualFold(t.ID, id) {
			return t, true
		}
	}
	return Technique{}, false
}

func startSpinner(message string) func() {
	done := make(chan struct{})

	go func() {
		frames := []rune{'|', '/', '-', '\\'}
		i := 0
		for {
			select {
			case <-done:
				fmt.Printf("\r%s... done\n", message)

				return
			default:
				fmt.Printf("\r%s... %c", message, frames[i%len(frames)])
				time.Sleep(120 * time.Millisecond)
				i++
			}
		}
	}()

	return func() { close(done) }
}

func humanSize(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
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
