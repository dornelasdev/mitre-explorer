package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

func main() {
	fmt.Println("MITRE Explorer v0.7.3")

	if len(os.Args) < 2 {
		startInteractiveMode()
		return
	}

	runCommand(os.Args[1:])
}

func startInteractiveMode() {

	useColor = true

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println("Choose mode:")
		fmt.Println("  [1] Guided Explorer")
		fmt.Println("  [2] Manual Command Mode")
		fmt.Println("  [q] Quit")
		fmt.Print("> ")

		choice := readLine(reader)

		switch strings.ToLower(choice) {
		case "1":
			fmt.Println("Guided Explorer mode selected.")
			runGuidedExplorer()

		case "2":
			fmt.Println("Manual mode selected.")
			fmt.Println("Type a command (without `go run .`), for example:")
			fmt.Println("  search powershell --limit 5 --detailed")
			fmt.Println("  show T1059")
			fmt.Println("  list --tactic execution --plain")
			fmt.Println("Type `back` to return to mode menu, or `q` to quit.")

			for {
				fmt.Print("manual> ")
				line := readLine(reader)
				if line == "" {
					continue
				}
				if strings.EqualFold(line, "back") {
					break
				}
				if strings.EqualFold(line, "q") {
					fmt.Println("Exiting.")
					return
				}

				cmdArgs := strings.Fields(line)
				runCommand(cmdArgs)
			}
		case "q":
			fmt.Println("Exiting.")
			return

		default:
			fmt.Println("Invalid choice.")
		}
	}
}

func runGuidedExplorer() {
	cache, err := loadCacheData(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println(errText("Cache not found. Run: go run . update"))
			return
		}
		fmt.Printf("Error loading cache: %v\n", err)
		return
	}

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println(title("Guided Explorer"))
		fmt.Println("  [1] Explore Tactics")
		fmt.Println("  [2] Explore Groups")
		fmt.Println("  [3] Explore Mitigations")
		fmt.Println("  [4] Explore Softwares")
		fmt.Println("  [q] Exit guided mode")
		fmt.Printf("> ")

		choice := strings.ToLower(strings.TrimSpace(readLine(reader)))

		switch choice {
		case "1":
			techniques := cache.Techniques
			tactics := collectUniqueTactics(techniques)
			if len(tactics) == 0 {
				fmt.Println("No tactics found in cache.")
				continue
			}

			for {
				fmt.Println("Select a tactic (number), or 'q' to return:")
				for i, t := range tactics {
					fmt.Printf("  [%d] %s\n", i+1, t)
				}
				fmt.Print("> ")

				tacticInput := readLine(reader)
				if strings.EqualFold(tacticInput, "q") {
					break
				}

				tacticIndex, err := strconv.Atoi(tacticInput)
				if err != nil || tacticIndex < 1 || tacticIndex > len(tactics) {
					fmt.Println("Invalid selection.")
					continue
				}

				selectedTactic := tactics[tacticIndex-1]
				results := listByTactic(techniques, selectedTactic)
				if len(results) == 0 {
					fmt.Println("No techniques found for this tactic.")
					continue
				}

				for {
					fmt.Println(title("Techniques"))
					fmt.Printf("%s %q (%d)\n", ok("Tactic:"), selectedTactic, len(results))
					printTechniqueTable(results)
					fmt.Println("  [b] Back to tactics")
					fmt.Println("  [q] Return to guided menu")
					fmt.Print("> ")

					pickInput := readLine(reader)

					if strings.EqualFold(pickInput, "q") {
						goto guidedMenu
					}
					if strings.EqualFold(pickInput, "b") {
						break
					}

					pick, err := strconv.Atoi(pickInput)
					if err != nil || pick < 1 || pick > len(results) {
						fmt.Println("Invalid selection.")
						continue
					}

					selected := results[pick-1]
					fmt.Println()
					printTechniqueDetails(selected)
				}
			}
		case "2":
			if len(cache.Groups) == 0 {
				fmt.Println("No groups found in cache.")
				continue
			}

			groups := make([]Group, len(cache.Groups))
			copy(groups, cache.Groups)
			sort.Slice(groups, func(i, j int) bool { return groups[i].ID < groups[j].ID })

			for {
				fmt.Println(title("Groups"))
				fmt.Printf("%s %d group(s)\n", ok("Found"), len(groups))
				fmt.Printf("%-4s %-10s %s\n", "#", "ID", "Name")
				fmt.Println(strings.Repeat("-", 64))
				for i, g := range groups {
					fmt.Printf("%-4d %-10s %s\n", i+1, g.ID, truncateText(g.Name, 48))
				}
				fmt.Println("  [q] Return to guided menu")
				fmt.Print("> ")

				input := readLine(reader)
				if strings.EqualFold(input, "q") {
					break
				}

				idx, err := strconv.Atoi(input)
				if err != nil || idx < 1 || idx > len(groups) {
					fmt.Println("Invalid selection.")
					continue
				}

				g := groups[idx-1]
				related := techniquesUsedByGroup(cache, g.ID)

				fmt.Printf("%s %s\n", label("ID:"), g.ID)
				fmt.Printf("%s %s\n", label("Name:"), g.Name)
				fmt.Printf("%s %s\n", label("Aliases:"), strings.Join(g.Aliases, ", "))
				fmt.Printf("%s %d\n", label("Mapped techniques:"), len(related))
				fmt.Printf("%s %s\n", label("Description:"), g.Description)

				viewedMapped := false

				for {
					fmt.Println("\nNext:")
					if !viewedMapped {
						fmt.Println("  [1] View mapped techniques")
					}
					fmt.Println("  [b] Back to groups")
					fmt.Println("  [q] Return to guided menu")
					fmt.Print("> ")

					next := strings.ToLower(readLine(reader))
					switch next {
					case "1":
						if viewedMapped {
							fmt.Println("Invalid selection.")
							continue
						}
						if len(related) == 0 {
							fmt.Println("No mapped techniques for this group.")
						} else {
							printTechniqueTable(related)
						}
						viewedMapped = true

					case "b":
						fmt.Println()
						goto groupList
					case "q":
						goto guidedMenu
					default:
						fmt.Println("Invalid selection.")
					}
				}
			groupList:
			}

		case "3":
			if len(cache.Mitigations) == 0 {
				fmt.Println("No mitigations found in cache.")
				continue
			}

			mitigations := make([]Mitigation, len(cache.Mitigations))
			copy(mitigations, cache.Mitigations)
			sort.Slice(mitigations, func(i, j int) bool { return mitigations[i].ID < mitigations[j].ID })

			for {
				fmt.Println(title("Mitigations"))
				fmt.Printf("%s %d mitigation(s)\n", ok("Found"), len(mitigations))
				fmt.Printf("%-4s %-10s %s\n", "#", "ID", "Name")
				fmt.Println(strings.Repeat("-", 64))
				for i, m := range mitigations {
					fmt.Printf("%-4d %-10s %s\n", i+1, m.ID, truncateText(m.Name, 48))
				}
				fmt.Println("  [q] Return to guided menu")
				fmt.Print("> ")

				input := readLine(reader)
				if strings.EqualFold(input, "q") {
					break
				}

				idx, err := strconv.Atoi(input)
				if err != nil || idx < 1 || idx > len(mitigations) {
					fmt.Println("Invalid selection.")
					continue
				}

				m := mitigations[idx-1]
				related := techniquesMitigatedBy(cache, m.ID)

				fmt.Println()
				fmt.Printf("%s %s\n", label("ID:"), m.ID)
				fmt.Printf("%s %s\n", label("Name:"), m.Name)
				fmt.Printf("%s %d\n", label("Mapped techniques:"), len(related))
				fmt.Printf("%s %s\n", label("Description:"), m.Description)

				viewedMapped := false

				for {
					fmt.Println("\nNext:")
					if !viewedMapped {
						fmt.Println("  [1] View mapped techniques")
					}
					fmt.Println("  [b] Back to mitigations")
					fmt.Println("  [q] Return to guided menu")
					fmt.Print("> ")

					next := strings.ToLower(readLine(reader))
					switch next {
					case "1":
						if viewedMapped {
							fmt.Println("Invalid selection.")
							continue
						}
						if len(related) == 0 {
							fmt.Println("No mapped techniques for this mitigation.")
						} else {
							printTechniqueTable(related)
						}
						viewedMapped = true

					case "b":
						fmt.Println()
						goto mitigationList
					case "q":
						goto guidedMenu
					default:
						fmt.Println("Invalid selection.")
					}
				}
				mitigationList:
				}
		case "4":
			if len(cache.Softwares) == 0 {
				fmt.Println("No software found in cache.")
				continue
			}

			softwares := make([]Software, len(cache.Softwares))
			copy(softwares, cache.Softwares)
			sort.Slice(softwares, func(i, j int) bool { return softwares[i].ID < softwares[j].ID })
			for {
				fmt.Println(title("Software"))
				fmt.Printf("%s %d software item(s)\n", ok("Found"), len(softwares))
				fmt.Printf("%-4s %-10s %s\n", "#", "ID", "Name")
				fmt.Println(strings.Repeat("-", 64))
				for i, s := range softwares {
					fmt.Printf("%-4d %-10s %s\n", i+1, s.ID, truncateText(s.Name, 40))
				}
				fmt.Println("  [q] Return to guided menu")
				fmt.Print("> ")

				input := readLine(reader)
				if strings.EqualFold(input, "q") {
					break
				}

				idx, err := strconv.Atoi(input)
				if err != nil || idx < 1 || idx > len(softwares) {
					fmt.Println("Invalid selection.")
					continue
				}

				s := softwares[idx-1]
				related := techniquesUsedBySoftware(cache, s.ID)

				fmt.Println()
				fmt.Printf("%s %s\n", label("ID:"), s.ID)
				fmt.Printf("%s %s\n", label("Name:"), s.Name)
				fmt.Printf("%s %s\n", label("Type:"), s.Type)
				fmt.Printf("%s %s\n", label("Aliases:"), strings.Join(s.Aliases, ", "))
				fmt.Printf("%s %d\n", label("Mapped techniques:"), len(related))
				fmt.Printf("%s %s\n", label("Description:"), s.Description)

				viewedMapped := false
				for {
					fmt.Println("\nNext:")
					if !viewedMapped {
						fmt.Println("  [1] View mapped techniques")
					}
					fmt.Println("  [b] Back to software techniques")
					fmt.Println("  [q] Return to guided menu")
					fmt.Print("> ")

					next := strings.ToLower(readLine(reader))
					switch next {
					case "1":
						if viewedMapped {
							fmt.Println("Invalid selection.")
							continue
						}
						if len(related) == 0 {
							fmt.Println("No mapped techniques for this software.")
						} else {
							printTechniqueTable(related)
						}
						viewedMapped = true

					case "b":
						fmt.Println()
						goto softwareList
					case "q":
						goto guidedMenu
					default:
						fmt.Println("Invalid selection.")
					}
				}
			softwareList:
			}

		case "q":
			fmt.Println("Exiting guided explorer.")
			return
		default:
			fmt.Println("Invalid selection.")
		}

	guidedMenu:
	}
}

func printTechniqueDetails(t Technique) {
	fmt.Printf("ID: %s\n", t.ID)
	fmt.Printf("Name: %s\n", t.Name)
	fmt.Printf("Description: %s\n", t.Description)
	fmt.Printf("Tactics: %s\n", strings.Join(t.Tactics, ", "))
	fmt.Printf("Platforms: %s\n", strings.Join(t.Platforms, ", "))
	fmt.Printf("Data Sources: %s\n", strings.Join(t.DataSources, ", "))
	fmt.Printf("Detection Notes: %s\n", t.DetectionNotes)
}

func readLine(reader *bufio.Reader) string {
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func printMappedTechniquesWithMode(results []Technique, detailed bool) {
	if detailed {
		for i, t := range results {
			fmt.Printf("\n[%d] %s | %s\n", i+1, t.ID, t.Name)
			fmt.Printf("    Tactics: %s\n", strings.Join(t.Tactics, ", "))
			fmt.Printf("    Platforms: %s\n", strings.Join(t.Platforms, ", "))
		}
		return
	}
	printTechniqueTable(results)
}

func runCommand(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: go run . <command>")
		return
	}

	useColor = true

	command := args[0]

	filtered := make([]string, 0, len(args))
	filtered = append(filtered, command)

	for _, a := range args[1:] {
		if a == "--plain" {
			useColor = false
			continue
		}
		filtered = append(filtered, a)
	}
	args = filtered

	switch command {
	case "update":
		const sourceURL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
		const rawPath = "data/enterprise-attack.json"

		force := len(args) >= 2 && (args[1] == "-f" || args[1] == "--force")
		if len(args) > 2 {
			fmt.Println("Usage: go run . update [-f|--force] [--plain]")
			return
		}
		if len(args) == 2 && args[1] != "-f" && args[1] != "--force" {
			fmt.Println("Usage: go run . update [-f|--force] [--plain]")
			return
		}

		meta, err := loadUpdateMeta(metaPath)
		if err != nil && !os.IsNotExist(err) {
			fmt.Printf("Failed to read update metadata: %v\n", err)
			return
		}

		stop := startSpinner("Checking/downloading ATT&CK data")
		dl, err := downloadFileConditional(sourceURL, rawPath, meta, force)
		stop()
		if err != nil {
			fmt.Printf("Update failed: %v\n", err)
			return
		}

		if dl.NotModified {
			fmt.Println(warn("Remote dataset unchanged (304 Not Modified)."))
			if _, err := os.Stat(cachePath); err == nil {
				fmt.Println("Local cache is already up to date.")
				return
			}

			fmt.Println(warn("Cache file missing. Rebuilding cache from local raw dataset."))
		}

		if _, err := os.Stat(rawPath); err != nil {
			if os.IsNotExist(err) {
				fmt.Println("Raw dataset file is missing. Run: go run . update -f")
				return
			}
			fmt.Printf("Error checking raw dataset file: %v\n", err)
			return
		}

		if !dl.Downloaded {
			info, err := os.Stat(rawPath)
			if err != nil {
				fmt.Printf("Error reading raw dataset size: %v\n", err)
				return
			}
			dl.Bytes = info.Size()
		}

		cache, err := buildCacheDataFromSTIX(rawPath)
		if err != nil {
			fmt.Printf("Parse failed: %v\n", err)
			return
		}

		if err := saveCacheData(cachePath, cache); err != nil {
			fmt.Printf("Cache write failed: %v\n", err)
			return
		}

		if err := saveUpdateMeta(metaPath, UpdateMeta{
			ETag: dl.ETag,
			LastModified: dl.LastModified,
		}); err != nil {
			fmt.Printf("Warning: failed to save update metadata: %v\n", err)
		}

		fmt.Println(ok("Update complete."))
		fmt.Printf("Source: %s\n", sourceURL)
		fmt.Printf("Saved: %s\n", rawPath)
		fmt.Printf("Size: %s (%d bytes)\n", humanSize(dl.Bytes), dl.Bytes)
		fmt.Printf("Cache: %s\n", cachePath)
		fmt.Printf("Parsed techniques: %d\n", len(cache.Techniques))
		fmt.Printf("Parsed groups: %d\n", len(cache.Groups))
		fmt.Printf("Parsed mitigations: %d\n", len(cache.Mitigations))
		fmt.Printf("Parsed campaigns: %d\n", len(cache.Campaigns))
		fmt.Printf("Parsed relationships: %d\n", len(cache.Relationships))


		if dl.Downloaded {
			fmt.Println("Download status: downloaded new dataset")
		} else {
			fmt.Println("Download status: reused local raw dataset")
		}

	case "search":
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

	case "show":
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

	case "list":
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

	case "group":
		if len(args) < 3 {
			fmt.Println("Usage:")
			fmt.Println("  go run . group techniques <group_id_or_name> [--detailed] [--plain]")
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

		sub := strings.ToLower(args[1])

		switch sub {
		case "show":
			if len(args) < 3 {
				fmt.Println("Usage: go run . group show <group_id_or_name> [--plain]")
				return
			}

			groupInput := args[2]
			g, found := findGroup(cache, groupInput)
			if !found {
				fmt.Printf("Group %q not found in cache.\n", groupInput)
				return
			}

			related := techniquesUsedByGroup(cache, g.ID)

			fmt.Printf("%s %s\n", label("ID:"), g.ID)
			fmt.Printf("%s %s\n", label("Name:"), g.Name)
			fmt.Printf("%s %s\n", label("Aliases:"), strings.Join(g.Aliases, ", "))
			fmt.Printf("%s %d\n", label("Mapped techniques:"), len(related))
			fmt.Printf("%s %s\n", label("Description:"), g.Description)

		case "techniques":
			detailed := false
			filtered := make([]string, 0, len(args))
			filtered = append(filtered, args[0], args[1])

			for _, a := range args[2:] {
				if a == "--detailed" {
					detailed = true
					continue
				}
				if strings.HasPrefix(a, "-") {
					fmt.Println("Usage: go run . group techniques <group_id_or_name> [--detailed] [--plain]")
					return
				}
				filtered = append(filtered, a)
			}
			args = filtered

			if len(args) != 3 {
				fmt.Println("Usage: go run . group techniques <group_id_or_name> [--detailed] [--plain]")
				return
			}

			groupInput := args[2]
			g, found := findGroup(cache, groupInput)
			if !found {
				fmt.Printf("Group %q not found in cache.\n", groupInput)
				return
			}

			results := techniquesUsedByGroup(cache, g.ID)
			if len(results) == 0 {
				fmt.Printf("No techniques mapped for group %s (%s).\n", g.Name, g.ID)
				return
			}

			fmt.Printf("%s %s (%s)\n", label("Group:"), g.Name, g.ID)
			fmt.Printf("%s %d technique(s)\n", ok("Found"), len(results))

			printMappedTechniquesWithMode(results, detailed)

		default:
			fmt.Printf("Unknown group subcommand: %s\n", sub)
			fmt.Println("Use: group techniques <group_id_or_name>")
		}
	case "mitigation":
		if len(args) < 3 {
			fmt.Println("Usage:")
			fmt.Println("  go run . mitigation techniques <mitigation_id_or_name> [--detailed] [--plain]")
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

		sub := strings.ToLower(args[1])

		switch sub {
		case "techniques":
			detailed := false
			filtered := make([]string, 0, len(args))
			filtered = append(filtered, args[0], args[1])

			for _, a := range args[2:] {
				if a == "--detailed" {
					detailed = true
					continue
				}
				if strings.HasPrefix(a, "-") {
					fmt.Println("Usage: go run . mitigation techniques <mitigation_id_or_name> [--detailed] [--plain]")
					return
				}
				filtered = append(filtered, a)
			}
			args = filtered

			if len(args) != 3 {
				fmt.Println("Usage: go run . mitigation techniques <mitigation_id_or_name> [--detailed] [--plain]")
				return
			}

			mitInput := args[2]
			m, found := findMitigation(cache, mitInput)

			if !found {
				fmt.Printf("Mitigation %q not found in cache.\n", mitInput)
				return
			}

			results := techniquesMitigatedBy(cache, m.ID)

			if len(results) == 0 {
				fmt.Printf("No techniques mapped for mitigation %s (%s).\n", m.Name, m.ID)
				return
			}

			fmt.Printf("%s %s (%s)\n", label("Mitigation:"), m.Name, m.ID)
			fmt.Printf("%s %d technique(s)\n", ok("Found"), len(results))

			printMappedTechniquesWithMode(results, detailed)

		default:
			fmt.Printf("Unknown mitigation subcommand: %s\n", sub)
			fmt.Println("Use: mitigation techniques <mitigation_id_or_name>")
		}
	case "software":
		if len(args) < 3 {
			fmt.Println("Usage:")
			fmt.Println("  go run . software show <software_id_or_name> [--plain]")
			fmt.Println("  go run . software techniques <software_id_or_name> [--detailed] [--plain]")
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

		sub := strings.ToLower(args[1])

		switch sub {
		case "show":
			if len(args) != 3 {
				fmt.Println("Usage: go run . software show <software_id_or_name> [--plain]")
				return
			}

			softwareInput := args[2]
			s, found := findSoftware(cache, softwareInput)
			if !found {
				fmt.Printf("Software %q not found in cache.\n", softwareInput)
				return
			}

			related := techniquesUsedBySoftware(cache, s.ID)
			fmt.Printf("%s %s\n", label("ID:"), s.ID)
			fmt.Printf("%s %s\n", label("Name:"), s.Name)
			fmt.Printf("%s %s\n", label("Type:"), s.Type)
			fmt.Printf("%s %s\n", label("Aliases:"), strings.Join(s.Aliases, ", "))
			fmt.Printf("%s %d\n", label("Mapped techniques:"), len(related))
			fmt.Printf("%s %s\n", label("Description:"), s.Description)

		case "techniques":
			detailed := false
			filtered := make([]string, 0, len(args))
			filtered = append(filtered, args[0], args[1])

			for _, a := range args[2:] {
				if a == "--detailed" {
					detailed = true
					continue
				}
				if strings.HasPrefix(a, "-") {
					fmt.Println("Usage: go run . software techniques <software_id_or_name> [--detailed] [--plain]")
					return
				}
				filtered = append(filtered, a)
			}
			args = filtered

			if len(args) != 3 {
				fmt.Println("Usage: go run . software techniques <software_id_or_name> [--detailed] [--plain]")
				return
			}

			softwareInput := args[2]
			s, found := findSoftware(cache, softwareInput)
			if !found {
				fmt.Printf("Software %q not found in cache.\n", softwareInput)
				return
			}

			results := techniquesUsedBySoftware(cache, s.ID)
			if len(results) == 0 {
				fmt.Printf("No techniques mapped for software %s (%s).\n", s.Name, s.ID)
				return
			}

			fmt.Printf("%s %s (%s)\n", label("Software:"), s.Name, s.ID)
			fmt.Printf("%s %d technique(s)\n", ok("Found"), len(results))

			printMappedTechniquesWithMode(results, detailed)

		default:
			fmt.Printf("Unknown software subcommand: %s\n", sub)
			fmt.Println("Use: software show <software_id_or_name> or software techniques <software_id_or_name>")
		}
	case "campaign":
		if len(args) < 3 {
			fmt.Println("Usage:")
			fmt.Println("  go run . campaign show <campaign_id_or_name> [--plain]")
			fmt.Println("  go run . campaign techniques <campaign_id_or_name> [--detailed] [--plain]")
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

		sub := strings.ToLower(args[1])

		switch sub {
		case "show":
			if len(args) != 3 {
				fmt.Println("Usage: go run . campaign show <campaign_id_or_name> [--plain]")
				return
			}
			campaignInput := args[2]
			c, found := findCampaign(cache, campaignInput)
			if !found {
				fmt.Printf("Campaign %q not found in cache.\n", campaignInput)
				return
			}

			related := techniquesUsedByCampaign(cache, c.ID)
			fmt.Printf("%s %s\n", label("ID:"), c.ID)
			fmt.Printf("%s %s\n", label("Name:"), c.Name)
			fmt.Printf("%s %s\n", label("Aliases:"), strings.Join(c.Aliases, ", "))
			fmt.Printf("%s %d\n", label("Mapped techniques:"), len(related))
			fmt.Printf("%s %s\n", label("Description:"), c.Description)

		case "techniques":
			detailed := false
			filtered := make([]string, 0, len(args))
			filtered = append(filtered, args[0], args[1])

			for _, a := range args[2:] {
				if a == "--detailed" {
					detailed = true
					continue
				}
				if strings.HasPrefix(a, "-") {
					fmt.Println("Usage: go run . campaign techniques <campaign_id_or_name> [--detailed] [--plain]")
					return
				}
				filtered = append(filtered, a)
			}
			args = filtered

			if len(args) != 3 {
				fmt.Println("Usage: go run . campaign techniques <campaign_id_or_name> [--detailed] [--plain]")
				return
			}
			campaignInput := args[2]
			c, found := findCampaign(cache, campaignInput)
			if !found {
				fmt.Printf("Campaign %q not found in cache.\n", campaignInput)
				return
			}

			results := techniquesUsedByCampaign(cache, c.ID)
			if len(results) == 0 {
				fmt.Printf("No techniques mapped for campaign %s (%s).\n", c.Name, c.ID)
				return
			}

			fmt.Printf("%s %s (%s)\n", label("Campaign:"), c.Name, c.ID)
			fmt.Printf("%s %d technique(s)\n", ok("Found"), len(results))
			printMappedTechniquesWithMode(results, detailed)

		default:
			fmt.Printf("Unknown campaign subcommand: %s\n", sub)
			fmt.Println("Use: campaign show <campaign_id_or_name> or campaign techniques <campaign_id_or_name>")
		}

	default:
		fmt.Printf("Unknown command: %s\n", command)
	}
}

