package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
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

func main() {
	fmt.Println("MITRE Explorer v0.1")

	if len(os.Args) < 2 {
		fmt.Println("Usage: go run . <command>")
		return
	}

	command := os.Args[1]

	techniques, err := loadTechniques("data/techniques.json")
	if err != nil {
		fmt.Printf("Error loading data: %v\n", err)
		return
	}

	fmt.Printf("Loaded %d techniques\n", len(techniques))

	switch command {
	case "search":
		if len(os.Args) < 3 {
			fmt.Println("Usage: go run . search <term>")
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
			fmt.Printf("- %s | %s", r.ID, r.Name)
		}

	case "show":
		if len(os.Args) < 3 {
			fmt.Println("Usage: go run . show <technique_id>")
			return
		}
		id := os.Args[2]
		technique, found := findTechniqueByID(techniques, id)

		if !found {
			fmt.Printf("Technique %s not found.\n", id)
			return
		}

		fmt.Printf("ID: %s\n", technique.ID)
		fmt.Printf("Name: %s\n", technique.Name)
		fmt.Printf("Description: %s\n", technique.Description)
		fmt.Printf("Tactics: %s\n", strings.Join(technique.Tactics, ", "))
		fmt.Printf("Platforms: %s\n", strings.Join(technique.Platforms, ", "))
		fmt.Printf("Data Sources: %s\n", strings.Join(technique.DataSources, ", "))
		fmt.Printf("Detection Notes: %s\n", strings.Join(technique.DataSources, ", "))

	default:
		fmt.Printf("Unknown command: %s\n", command)
	}
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
