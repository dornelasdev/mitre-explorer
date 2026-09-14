package cli

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"mitre-explorer/internal/attack"
)

func (app *App) printEntitySearchResults(results []attack.EntitySearchResult) {
	rows := make([][]string, 0, len(results))
	for _, r := range results {
		rows = append(rows, []string{
			r.Type,
			r.ID,
			truncateText(r.Name, 64),
		})
	}
	app.printEntityTable(
		[]string{"Type", "ID", "Name"},
		rows,
		[]int{16, 14, 64},
	)
}

func (app *App) handleSearch(args []string) error {
	if len(args) < 2 {
		return invalidUsage("search requires a term")
	}
	term := args[1]
	if err := requireOperand(term, "search term"); err != nil {
		return err
	}
	nameOnly, detailed, inDetection := false, false, false
	limit := 0
	target := "techniques"
	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--name-only":
			nameOnly = true
		case "--detailed":
			detailed = true
		case "--in-detection":
			inDetection = true
		case "--limit":
			value, err := optionValue(args, i)
			if err != nil {
				return err
			}
			n, err := strconv.Atoi(value)
			if err != nil || n <= 0 {
				return invalidUsage("--limit requires a positive integer")
			}
			limit = n
			i++
		case "--target":
			value, err := optionValue(args, i)
			if err != nil {
				return err
			}
			target = normalizeListTarget(value)
			i++
		default:
			return invalidUsage("unknown search option: %s", args[i])
		}
	}
	switch target {
	case "techniques", "groups", "mitigations", "software", "campaigns", "detections", "analytics", "data-components", "all":
	default:
		return invalidUsage("unknown search target: %s", target)
	}
	if target != "techniques" && (inDetection || nameOnly || detailed) {
		return invalidUsage("--in-detection, --name-only, and --detailed are only supported for technique search")
	}
	cache, err := app.loadCacheForCommand()
	if err != nil {
		return err
	}
	techniques := cache.Techniques
	if target == "techniques" {
		var results []attack.Technique
		if inDetection {
			results = attack.SearchDetectionNotes(techniques, term, limit)
		} else {
			results = attack.SearchTechniques(techniques, term, nameOnly, limit)
		}
		if len(results) == 0 {
			fmt.Fprintln(app.out, "No techniques found.")
			return nil
		}
		fmt.Fprintf(app.out, "%s %d technique(s)\n", app.ok("Found"), len(results))
		app.printMappedTechniquesWithMode(results, detailed)
		return nil
	}

	results := attack.SearchEntities(cache, target, term, limit)
	if len(results) == 0 {
		fmt.Fprintf(app.out, "No results found for target %q.\n", target)
		return nil
	}

	fmt.Fprintf(app.out, "%s %d result(s)\n", app.ok("Found"), len(results))
	app.printEntitySearchResults(results)
	return nil
}

func (app *App) handleShow(args []string) error {
	if len(args) != 2 && !(len(args) == 3 && strings.EqualFold(args[1], "detection")) {
		return invalidUsage("show requires <technique_id> or detection <technique_id>")
	}
	if len(args) == 2 && strings.EqualFold(args[1], "detection") {
		return invalidUsage("show detection requires a technique ID")
	}
	if err := requireOperand(args[len(args)-1], "technique ID"); err != nil {
		return err
	}
	cache, err := app.loadCacheForCommand()
	if err != nil {
		return err
	}
	techniques := cache.Techniques
	id := args[len(args)-1]
	technique, found := attack.FindTechniqueByID(techniques, id)

	if !found {
		return fmt.Errorf("technique %s not found in cache", id)
	}

	fmt.Fprintf(app.out, "%s %s\n", app.label("ID:"), technique.ID)
	fmt.Fprintf(app.out, "%s %s\n", app.label("Name:"), technique.Name)
	if len(args) == 3 {
		fmt.Fprintf(app.out, "%s %s\n", app.label("Detection Notes:"), technique.DetectionNotes)
		return nil
	}
	fmt.Fprintf(app.out, "%s %s\n", app.label("Description:"), technique.Description)
	fmt.Fprintf(app.out, "%s %s\n", app.label("Tactics:"), strings.Join(technique.Tactics, ", "))
	fmt.Fprintf(app.out, "%s %s\n", app.label("Platforms:"), strings.Join(technique.Platforms, ", "))
	fmt.Fprintf(app.out, "%s %s\n", app.label("Data Sources:"), strings.Join(technique.DataSources, ", "))
	fmt.Fprintf(app.out, "%s %s\n", app.label("Detection Notes:"), technique.DetectionNotes)
	fmt.Fprintf(app.out, "%s %s\n", app.label("Data Components:"), strings.Join(technique.DataComponents, ", "))
	return nil
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

func parseTechniqueListFilters(args []string) (tactic, platform, dataComponent string, err error) {
	for i := 0; i < len(args); i++ {
		if args[i] == "--tactic" || args[i] == "--platform" || args[i] == "--data-component" {
			if _, err := optionValue(args, i); err != nil {
				return "", "", "", err
			}
		}
		switch args[i] {
		case "--tactic":
			tactic = args[i+1]
			i++
		case "--platform":
			platform = args[i+1]
			i++
		case "--data-component":
			dataComponent = args[i+1]
			i++
		default:
			return "", "", "", fmt.Errorf("unknown list option: %s", args[i])
		}
	}
	return tactic, platform, dataComponent, nil
}

func techniqueRows(techniques []attack.Technique) [][]string {
	rows := make([][]string, 0, len(techniques))
	for _, t := range techniques {
		rows = append(rows, []string{
			t.ID,
			truncateText(t.Name, 72),
		})
	}
	return rows
}

func (app *App) handleList(args []string) error {
	if len(args) < 2 {
		return invalidUsage("list requires a target")
	}
	entity := normalizeListTarget(args[1])
	tactic, platform, dataComponent := "", "", ""
	switch entity {
	case "techniques":
		var err error
		tactic, platform, dataComponent, err = parseTechniqueListFilters(args[2:])
		if err != nil {
			return invalidUsage("list techniques: %v", err)
		}
	case "groups", "mitigations", "software", "campaigns", "detections", "analytics", "data-components", "tactics", "platforms":
		if len(args) > 2 {
			return invalidUsage("list %s does not accept filters", entity)
		}
	default:
		return invalidUsage("unknown list target: %s", args[1])
	}
	cache, err := app.loadCacheForCommand()
	if err != nil {
		return err
	}
	const pageSize = 25
	switch entity {
	case "techniques":
		results := cache.Techniques
		titleText := "Techniques"

		if len(args) > 2 {
			results = attack.FilterTechniques(cache, attack.TechniqueFilters{
				Tactic:        tactic,
				Platform:      platform,
				DataComponent: dataComponent,
			})

			if tactic != "" {
				titleText = fmt.Sprintf("Techniques by tactic: %s", tactic)
			}
			if platform != "" {
				titleText = fmt.Sprintf("Techniques by platform: %s", platform)
			}
			if dataComponent != "" {
				titleText = fmt.Sprintf("Techniques by data component: %s", dataComponent)
			}
		}

		app.printPaginatedTable(
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

		app.printPaginatedTable(
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

		app.printPaginatedTable(
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

		app.printPaginatedTable(
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

		app.printPaginatedTable(
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

		app.printPaginatedTable(
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

		app.printPaginatedTable(
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

		app.printPaginatedTable(
			"Data Components",
			[]string{"Name"},
			rows,
			[]int{72},
			pageSize,
		)

	case "tactics":
		tactics := attack.CollectUniqueTactics(cache.Techniques, app.matrix.TacticOrder)
		rows := make([][]string, 0, len(tactics))
		for _, tactic := range tactics {
			rows = append(rows, []string{
				tactic,
			})
		}

		app.printPaginatedTable(
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

		app.printPaginatedTable(
			"Platforms",
			[]string{"Name"},
			rows,
			[]int{72},
			pageSize,
		)
	default:
		return invalidUsage("unknown list target: %s", args[1])
	}
	return nil
}
