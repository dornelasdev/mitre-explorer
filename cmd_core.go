package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func handleSearch(args []string) {
	if len(args) < 2 {
			fmt.Println("Usage: go run . search <term> [--name-only] [--limit N] [--detailed] [--plain]")
			return
		}
		cache, err := loadCacheData(cachePath)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Println(errText("Cache not found. Run: go run . update"))
				return
			}
			fmt.Printf("Error loading cache: %v\n", err)
			return
		}
		techniques := cache.Techniques

		term := args[1]
		nameOnly := false
		detailed := false
		limit := 0

		for i := 2; i < len(args); i++ {
			switch args[i] {
			case "--name-only":
				nameOnly = true
			case "--limit":
				if i+1 >= len(args) {
					fmt.Println("Usage: --limit <integer>")
					return
				}
				n, err := strconv.Atoi(args[i+1])
				if err != nil || n <= 0 {
					fmt.Println("Usage: --limit <integer>")
					return
				}
				limit = n
				i++
			case "--detailed":
				detailed = true
			default:
				fmt.Printf("Unknown search option: %s\n", args[i])
				fmt.Println("Use --name-only and/or --limit N")
				return
			}
		}

		results := searchTechniques(techniques, term, nameOnly, limit)

		if len(results) == 0 {
			fmt.Println("No techniques found.")
			return
		}

		fmt.Printf("%s %d technique(s)\n", ok("Found"), len(results))
		printMappedTechniquesWithMode(results, detailed)
}

func handleShow(args []string) {
	if len(args) < 2 {
			fmt.Println("Usage: go run . show <technique_id>")
			return
		}
		cache, err := loadCacheData(cachePath)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Println("Cache not found. Run: go run . update")
				return
			}
			fmt.Printf("Error loading cache: %v\n", err)
			return
		}
		techniques := cache.Techniques

		id := args[1]
		technique, found := findTechniqueByID(techniques, id)

		if !found {
			fmt.Printf("Technique %s not found in cache. Try: go run . update\n", id)
			return
		}

		fmt.Printf("%s %s\n", label("ID:"), technique.ID)
		fmt.Printf("%s %s\n", label("Name:"), technique.Name)
		fmt.Printf("%s %s\n", label("Description:"), technique.Description)
		fmt.Printf("%s %s\n", label("Tactics:"), strings.Join(technique.Tactics, ", "))
		fmt.Printf("%s %s\n", label("Platforms:"), strings.Join(technique.Platforms, ", "))
		fmt.Printf("%s %s\n", label("Data Sources:"), strings.Join(technique.DataSources, ", "))
		fmt.Printf("%s %s\n", label("Detection Notes:"), technique.DetectionNotes)
}

func handleList(args []string) {
	if len(args) < 3 {
			fmt.Println("Usage:")
			fmt.Println("  go run . list --tactic <name> [--detailed] [--plain]")
			fmt.Println("  go run . list --platform <name> [--detailed] [--plain]")
			return
		}

		cache, err := loadCacheData(cachePath)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Println(errText("Cache not found. Run: go run . update"))
				return
			}
			fmt.Printf("Error loading cache: %v\n", err)
			return
		}
		techniques := cache.Techniques

		detailed := false
		filtered := make([]string, 0, len(args))
		filtered = append(filtered, args[0])

		for _, a := range args[1:] {
			if a == "--detailed" {
				detailed = true
				continue
			}
			filtered = append(filtered, a)
		}
		args = filtered
		flag := args[1]
		value := args[2]

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

		fmt.Printf("%s %d technique(s)\n", ok("Found"), len(results))
		printMappedTechniquesWithMode(results, detailed)
}
