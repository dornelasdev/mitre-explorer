package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

type EntitySearchResult struct {
	Type string
	ID string
	Name string
}

func appendEntitySearchResult(results []EntitySearchResult, entityType, id, name, description, term string) []EntitySearchResult {
	if containsIgnoreCase(id, term) || containsIgnoreCase(name, term) || containsIgnoreCase(description, term) {
		return append(results, EntitySearchResult{
			Type: entityType,
			ID: id,
			Name: name,
		})
	}
	return results
}

func searchEntities(cache CacheData, target, term string, limit int) []EntitySearchResult {
	var results []EntitySearchResult

	addGroups := target == "groups" || target == "all"
	addMitigations := target == "mitigations" || target == "all"
	addSoftware := target == "software" || target == "all"
	addCampaigns := target == "campaigns" || target == "all"
	addDetections := target == "detections" || target == "all"
	addAnalytics := target == "analytics" || target == "all"
	addDataComponents := target == "data-components" || target == "all"

	if addGroups {
		for _, g := range cache.Groups {
			results = appendEntitySearchResult(results, "group", g.ID, g.Name, g.Description, term)
		}
	}

	if addMitigations {
		for _, m := range cache.Mitigations {
			results = appendEntitySearchResult(results, "mitigation", m.ID, m.Name, m.Description, term)
		}
	}

	if addSoftware {
		for _, s := range cache.Softwares {
			results = appendEntitySearchResult(results, "software", s.ID, s.Name, s.Description, term)
		}
	}

	if addCampaigns {
		for _, c := range cache.Campaigns {
			results = appendEntitySearchResult(results, "campaign", c.ID, c.Name, c.Description, term)
		}
	}

	if addDetections {
		for _, d := range cache.DetectionStrategies {
			results = appendEntitySearchResult(results, "detection", d.ID, d.Name, d.Description, term)
		}
	}

	if addAnalytics {
		for _, a := range cache.Analytics {
			results = appendEntitySearchResult(results, "analytic", a.ID, a.Name, a.Description, term)
		}
	}

	if addDataComponents {
		for _, dc := range cache.DataComponents {
			results = appendEntitySearchResult(results, "data-component", dc.ID, dc.Name, dc.Description, term)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Type != results[j].Type {
			return results[i].Type < results[j].Type
		}
		return results[i].Name < results[j].Name
	})

	if limit > 0 && len(results) > limit {
		results = results[:limit]
	}

	return results
}

func printEntitySearchResults(results []EntitySearchResult) {
	rows := make([][]string, 0, len(results))
	for _, r := range results {
		rows = append(rows, []string{
			r.Type,
			r.ID,
			truncateText(r.Name, 64),
		})
	}
	printEntityTable(
		[]string{"Type", "ID", "Name"},
		rows,
		[]int{16, 14, 64},
	)
}

func handleSearch(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: go run . search <term> [--target <target>] [--name-only] [--limit N] [--detailed] [--plain]")
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
	target := "techniques"

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
		case "--target":
			if i+1 >= len(args) {
				fmt.Println("Usage: --target <target>")
				return
			}
			target = normalizeListTarget(args[i+1])
			i++
		default:
			fmt.Printf("Unknown search option: %s\n", args[i])
			fmt.Println("Use --target, --name-only, --limit N, --detailed, and/or --in-detection")
			return
		}
	}

	if target == "techniques" {
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
		return
	}

	if inDetection || nameOnly || detailed {
		fmt.Println(errText("--in-detection, --name-only, and --detailed are only supported for technique search"))
		return
	}

	switch target {
	case "groups", "mitigations", "software", "campaigns", "detections", "analytics", "data-components", "all":
	default:
		fmt.Printf("Unknown search target: %s\n", target)
		fmt.Println("Targets: techniques | groups | mitigations | software | campaigns | detections | analytics | data-components | all")
		return
	}

	results := searchEntities(cache, target, term, limit)
	if len(results) == 0 {
		fmt.Printf("No results found for target %q.\n", target)
		return
	}

	fmt.Printf("%s %d result(s)\n", ok("Found"), len(results))
	printEntitySearchResults(results)
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

func normalizeListTarget(target string) string {
	switch strings.ToLower(target) {
	case "technique", "techniques", "tech", "techs":
		return "techniques"
	case "group", "groups":
		return "groups"
	case "mitigation", "mitigations":
		return "mitigations"
	case "software", "softwares":
		return "software"
	case "campaign", "campaigns":
		return "campaigns"
	case "detection", "detections", "det", "dets":
		return "detections"
	case "analytic", "analytics":
		return "analytics"
	case "data-component", "data-components", "dc", "dcs":
		return "data-components"
	case "tactic", "tactics":
		return "tactics"
	case "platform", "platforms":
		return "platforms"
	default:
		return strings.ToLower(target)
	}
}

func printListTargets() {
	fmt.Println("Targets: techniques | groups | mitigations | software | campaigns | detections | analytics | data-components | tactics | platforms")
}

func parseTechniqueListFilters(args []string) (tactic, platform, dataComponent string, err error) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--tactic":
			if i+1 >= len(args) {
				return "", "", "", fmt.Errorf("--tactic requires a value")
			}
			tactic = args[i+1]
			i++
		case "--platform":
			if i+1 >= len(args) {
				return "", "", "", fmt.Errorf("--platform requires a value")
			}
			platform = args[i+1]
			i++
		case "--data-component":
			if i+1 >= len(args) {
				return "", "", "", fmt.Errorf("--data-component requires a value")
			}
			dataComponent = args[i+1]
			i++
		default:
			return "", "", "", fmt.Errorf("unknown list option: %s", args[i])
		}
	}
	return tactic, platform, dataComponent, nil
}

func techniqueRows(techniques []Technique) [][]string {
	rows := make([][]string, 0, len(techniques))
	for _, t := range techniques {
		rows = append(rows, []string{
			t.ID,
			truncateText(t.Name, 72),
		})
	}
	return rows
}

func handleList(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: go run . list <target> [filters]")
		printListTargets()
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

	entity := normalizeListTarget(args[1])
	const pageSize = 25

	switch entity {
	case "techniques":
		results := cache.Techniques
		titleText := "Techniques"

		if len(args) > 2 {
			tactic, platform, dataComponent, err := parseTechniqueListFilters(args[2:])
			if err != nil {
				fmt.Println(errText(err.Error()))
				fmt.Println("Usage: go run . list techniques [--tactic <name>] [--platform <name>] [--data-component <name>]")
				return
			}

			if tactic != "" {
				results = listByTactic(results, tactic)
				titleText = fmt.Sprintf("Techniques by tactic: %s", tactic)
			}
			if platform != "" {
				results = listByPlatform(results, platform)
				titleText = fmt.Sprintf("Techniques by platform: %s", platform)
			}
			if dataComponent != "" {
				results = techniquesByDataComponent(cache, dataComponent)
				titleText = fmt.Sprintf("Techniques by data component: %s", dataComponent)
			}
		}

		printPaginatedTable(
			titleText,
			[]string{"ID", "Name"},
			techniqueRows(results),
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
		fmt.Printf("Unknown list target: %s\n", args[1])
		printListTargets()
	}
}
