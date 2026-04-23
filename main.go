package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	fmt.Println("MITRE Explorer v0.4")

	if len(os.Args) < 2 {
		fmt.Println("Usage: go run . <command>")
		return
	}

	command := os.Args[1]

	switch command {
	case "update":
		const sourceURL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
		const rawPath = "data/enterprise-attack.json"

		force := len(os.Args) >= 3 && (os.Args[2] == "-f" || os.Args[2] == "--force")

		var n int64
		if !force {
			if info, err := os.Stat(rawPath); err == nil {
				n = info.Size()
				fmt.Printf("Raw file already exists: %s\n", rawPath)
				fmt.Println("Skipping download. Use `go run . update --force or -f` to re-download")
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
			fmt.Println("Usage: go run . search <term> [--name-only] [--limit N]")
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
		nameOnly := false
		limit := 0

		for i := 3; i < len(os.Args); i++ {
			switch os.Args[i] {
			case "--name-only":
				nameOnly = true
			case "--limit":
				if i+1 >= len(os.Args) {
					fmt.Println("Usage: --limit <integer>")
					return
				}
				n, err := strconv.Atoi(os.Args[i+1])
				if err != nil || n <= 0 {
					fmt.Println("Usage: --limit <integer>")
					return
				}
				limit = n
				i++
			default:
				fmt.Printf("Unknown search option: %s\n", os.Args[i])
				fmt.Println("Use --name-only and/or --limit N")
				return
			}
		}

		results := searchTechniques(techniques, term, nameOnly, limit)

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

	case "list":
		if len(os.Args) < 4 {
			fmt.Println("Usage:")
			fmt.Println("  go run . list --tactic <name>")
			fmt.Println("  go run . list --platform <name>")
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

		flag := os.Args[2]
		value := os.Args[3]

		var results []Technique
		switch flag {
		case "--tactic":
			results = listByTactic(techniques, value)
		case "--platform":
			results = listByPlatform(techniques, value)
		default:
			fmt.Printf("Unknown list option: %s\n", flag)
			fmt.Println("Use --tactic or --platform")
			return
		}

		if len(results) == 0 {
			fmt.Println("No techniques found.")
			return
		}

		fmt.Printf("Found %d technique(s):\n", len(results))
		for _, t := range results {
			fmt.Printf("- %s | %s\n", t.ID, t.Name)
		}

	default:
		fmt.Printf("Unknown command: %s\n", command)
	}

}
