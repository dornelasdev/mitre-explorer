package main

import (
	"fmt"
	"os"
	"sort"
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
	inDetection := false

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
		case "--in-detection":
			inDetection = true
		default:
			fmt.Printf("Unknown search option: %s\n", args[i])
			fmt.Println("Use --name-only, --limit N, and/or --in-detection")
			return
		}
	}

	var results []Technique
	if inDetection {
		results = searchDetectionNotes(techniques, term, limit)
	} else {
		results = searchTechniques(techniques, term, nameOnly, limit)
	}

	if len(results) == 0 {
		fmt.Println("No techniques found.")
		return
	}

	fmt.Printf("%s %d technique(s)\n", ok("Found"), len(results))
	printMappedTechniquesWithMode(results, detailed)
}

func handleShow(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  go run . show <technique_id>")
		fmt.Println("  go run . show detection <technique_id>")
		return
	}
	if len(args) == 2 && strings.EqualFold(args[1], "detection") {
		fmt.Println("Usage: go run . show detection <technique_id>")
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

	if len(args) == 3 && strings.EqualFold(args[1], "detection") {
		id := args[2]
		technique, found := findTechniqueByID(techniques, id)
		if !found {
			fmt.Printf("Technique %s not found in cache. Try: go run . update\n", id)
			return
		}

		fmt.Printf("%s %s\n", label("ID:"), technique.ID)
		fmt.Printf("%s %s\n", label("Name:"), technique.Name)
		fmt.Printf("%s %s\n", label("Detection Notes:"), technique.DetectionNotes)
		return
	}

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
	fmt.Printf("%s %s\n", label("Data Components:"), strings.Join(technique.DataComponents, ", "))
}

func handleList(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: go run . list <target>")
		fmt.Println("Targets: techniques | groups | mitigations | software | campaigns | detections | analytics | data-components | tactics | platforms")
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

	entity := strings.ToLower(args[1])
	const pageSize = 25

	switch entity {
	case "techniques":
		rows := make([][]string, 0, len(cache.Techniques))
		for _, t := range cache.Techniques {
			rows = append(rows, []string{
				t.ID,
				truncateText(t.Name, 72),
			})
		}

		printPaginatedTable(
			"Techniques",
			[]string{"ID", "Name"},
			rows,
			[]int{12, 72},
			pageSize,
		)

	case "groups":
		rows := make([][]string, 0, len(cache.Groups))
		for _, g := range cache.Groups {
			rows = append(rows, []string{
				g.ID,
				truncateText(g.Name, 60),
			})
		}

		printPaginatedTable(
			"Groups",
			[]string{"ID", "Name"},
			rows,
			[]int{10, 60},
			pageSize,
		)
	
	case "mitigations":
		rows := make([][]string, 0, len(cache.Mitigations))
		for _, m := range cache.Mitigations {
			rows = append(rows, []string{
				m.ID,
				truncateText(m.Name, 60),
			})
		}

		printPaginatedTable(
			"Mitigations",
			[]string{"ID", "Name"},
			rows,
			[]int{10, 60},
			pageSize,
		)
	
	case "software":
		rows := make([][]string, 0, len(cache.Softwares))
		for _, s := range cache.Softwares {
			rows = append(rows, []string{
				s.ID,
				truncateText(s.Name, 60),
			})
		}

		printPaginatedTable(
			"Software",
			[]string{"ID", "Name"},
			rows,
			[]int{10, 60},
			pageSize,
		)
	
	case "campaigns":
		rows := make([][]string, 0, len(cache.Campaigns))
		for _, c := range cache.Campaigns {
			rows = append(rows, []string{
				c.ID,
				truncateText(c.Name, 60),
			})
		}

		printPaginatedTable(
			"Campaigns",
			[]string{"ID", "Name"},
			rows,
			[]int{10, 60},
			pageSize,
		)
	
	case "detections":
		rows := make([][]string, 0, len(cache.DetectionStrategies))
		for _, d := range cache.DetectionStrategies {
			rows = append(rows, []string{
				d.ID,
				truncateText(d.Name, 60),
			})
		}

		printPaginatedTable(
			"Detection Strategies",
			[]string{"ID", "Name"},
			rows,
			[]int{12, 60},
			pageSize,
		)
	
	case "analytics":
		rows := make([][]string, 0, len(cache.Analytics))
		for _, a := range cache.Analytics {
			rows = append(rows, []string{
				a.ID,
				truncateText(a.Name, 60),
			})
		}

		printPaginatedTable(
			"Analytics",
			[]string{"ID", "Name"},
			rows,
			[]int{12, 60},
			pageSize,
		)
	
	case "data-components":
		rows := make([][]string, 0, len(cache.DataComponents))
		for _, dc := range cache.DataComponents {
			rows = append(rows, []string{
				truncateText(dc.Name, 72),
			})
		}

		printPaginatedTable(
			"Data Components",
			[]string{"Name"},
			rows,
			[]int{72},
			pageSize,
		)
	
	case "tactics":
		tactics := collectUniqueTactics(cache.Techniques)
		rows := make([][]string, 0, len(tactics))
		for _, tactic := range tactics {
			rows = append(rows, []string{
				tactic,
			})
		}

		printPaginatedTable(
			"Tactics",
			[]string{"Tactic"},
			rows,
			[]int{72},
			pageSize,
		)
	
	case "platforms":
		seen := make(map[string]bool)
		var platforms []string
		for _, t := range cache.Techniques {
			for _, p := range t.Platforms {
				if _, ok := seen[p]; ok {
					continue
				}
				seen[p] = true
				platforms = append(platforms, p)
			}
		}

		sort.Strings(platforms)

		rows := make([][]string, 0, len(platforms))
		for _, platform := range platforms {
			rows = append(rows, []string{
				platform,
			})
		}

		printPaginatedTable(
			"Platforms",
			[]string{"Name"},
			rows,
			[]int{72},
			pageSize,
		)
	default:
		fmt.Printf("Unknown list target: %s\n", entity)
		fmt.Println("Targets: techniques | groups | mitigations | software | campaigns | detections | analytics | data-components | tactics | platforms")
	}
}
