package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

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
		fmt.Println("  [4] Explore Software")
		fmt.Println("  [5] Explore Campaigns")
		fmt.Println("  [6] Explore Data Components")
		fmt.Println("  [7] Explore Detection Strategies")
		fmt.Println("  [8] Explore Analytics")
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
					fmt.Println("  [b] Back to software list")
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
		case "5":
			if len(cache.Campaigns) == 0 {
				fmt.Println("No campaigns found in cache.")
				continue
			}

			campaigns := make([]Campaign, len(cache.Campaigns))
			copy(campaigns, cache.Campaigns)
			sort.Slice(campaigns, func(i, j int) bool { return campaigns[i].ID < campaigns[j].ID })

			for {
				fmt.Println(title("Campaigns"))
				fmt.Printf("%s %d campaign(s)\n", ok("Found"), len(campaigns))
				fmt.Printf("%-4s %-10s %s\n", "#", "ID", "Name")
				fmt.Println(strings.Repeat("-", 64))
				for i, c := range campaigns {
					fmt.Printf("%-4d %-10s %s\n", i+1, c.ID, truncateText(c.Name, 48))
				}
				fmt.Println("  [q] Return to guided menu")
				fmt.Print("> ")

				input := readLine(reader)
				if strings.EqualFold(input, "q") {
					break
				}

				idx, err := strconv.Atoi(input)
				if err != nil || idx < 1 || idx > len(campaigns) {
					fmt.Println("Invalid selection.")
					continue
				}

				c := campaigns[idx-1]
				related := techniquesUsedByCampaign(cache, c.ID)

				fmt.Println()
				fmt.Printf("%s %s\n", label("ID:"), c.ID)
				fmt.Printf("%s %s\n", label("Name:"), c.Name)
				fmt.Printf("%s %s\n", label("Aliases:"), strings.Join(c.Aliases, ", "))
				fmt.Printf("%s %d\n", label("Mapped techniques:"), len(related))
				fmt.Printf("%s %s\n", label("Description:"), c.Description)

				viewedMapped := false
				for {
					fmt.Println("\nNext:")
					if !viewedMapped {
						fmt.Println("  [1] View mapped techniques")
					}
					fmt.Println("  [b] Back to campaigns")
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
							fmt.Println("No mapped techniques for this campaign.")
						} else {
							printTechniqueTable(related)
						}
						viewedMapped = true
					case "b":
						fmt.Println()
						goto campaignList
					case "q":
						goto guidedMenu
					default:
						fmt.Println("Invalid selection.")
					}
				}
			campaignList:
			}
		case "6":
			runGuidedDataComponents(cache, reader)

		case "7":
			runGuidedDetections(cache, reader)

		case "8":
			runGuidedAnalytics(cache, reader)

		case "q":
			fmt.Println("Exiting guided explorer.")
			return
		default:
			fmt.Println("Invalid selection.")
		}

	guidedMenu:
	}
}

func runGuidedDataComponents(cache CacheData, reader *bufio.Reader) {
	if len(cache.DataComponents) == 0 {
		fmt.Println("No data components found in cache.")
		return
	}

	components := make([]DataComponent, len(cache.DataComponents))
	copy(components, cache.DataComponents)
	sort.Slice(components, func(i, j int) bool { return components[i].Name < components[j].Name })

	for {
		fmt.Println(title("Data Components"))
		fmt.Printf("%s %d data component(s)\n", ok("Found"), len(components))
		fmt.Printf("%-4s %s\n", "#", "Name")
		fmt.Println(strings.Repeat("-", 64))

		for i, dc := range components {
			fmt.Printf("%-4d %s\n", i+1, truncateText(dc.Name, 56))
		}

		fmt.Println("  [q] Return to guided menu")
		fmt.Print("> ")

		input := readLine(reader)
		if strings.EqualFold(input, "q") {
			return
		}

		idx, err := strconv.Atoi(input)
		if err != nil || idx < 1 || idx > len(components) {
			fmt.Println("Invalid selection.")
			continue
		}

		dc := components[idx-1]
		related := techniquesByDataComponent(cache, dc.Name)

		fmt.Println()
		fmt.Printf("%s %s\n", label("Name:"), dc.Name)
		fmt.Printf("%s %d\n", label("Mapped techniques:"), len(related))
		fmt.Printf("%s %s\n", label("Description:"), dc.Description)

		viewedMapped := false

		for {
			fmt.Println("\nNext:")
			if !viewedMapped {
				fmt.Println("  [1] View mapped techniques")
			}
			fmt.Println("  [b] Back to data components")
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
					fmt.Println("No mapped techniques for this data component.")
				} else {
					printTechniqueTable(related)
				}
				viewedMapped = true
			case "b":
				fmt.Println()
				goto componentList
			case "q":
				return
			default:
				fmt.Println("Invalid selection.")
			}
		}
	componentList:
	}

}

func runGuidedDetections(cache CacheData, reader *bufio.Reader) {
	if len(cache.DetectionStrategies) == 0 {
		fmt.Println("No detection strategies found in cache.")
		return
	}

	detections := make([]DetectionStrategy, len(cache.DetectionStrategies))
	copy(detections, cache.DetectionStrategies)
	sort.Slice(detections, func(i, j int) bool { return detections[i].Name < detections[j].Name })

	for {
		fmt.Println(title("Detection Strategies"))
		fmt.Printf("%s %d detection strategy item(s)\n", ok("Found"), len(detections))
		fmt.Printf("%-4s %-12s %s\n", "#", "ID", "Name")
		fmt.Println(strings.Repeat("-", 76))

		for i, d := range detections {
			fmt.Printf("%-4d %-12s %s\n", i+1, d.ID, truncateText(d.Name, 56))
		}

		fmt.Println("  [q] Return to guided menu")
		fmt.Print("> ")

		input := readLine(reader)
		if strings.EqualFold(input, "q") {
			return
		}

		idx, err := strconv.Atoi(input)
		if err != nil || idx < 1 || idx > len(detections) {
			fmt.Println("Invalid selection.")
			continue
		}

		d := detections[idx-1]
		techniques := techniquesDetectedByStrategy(cache, d.ID)
		analytics := analyticsByDetectionStrategy(cache, d.ID)
		components := dataComponentsByDetectionStrategy(cache, d.ID)

		fmt.Println()
		fmt.Printf("%s %s\n", label("ID:"), d.ID)
		fmt.Printf("%s %s\n", label("Name:"), d.Name)
		fmt.Printf("%s %d\n", label("Mapped techniques:"), len(techniques))
		fmt.Printf("%s %d\n", label("Analytics:"), len(analytics))
		fmt.Printf("%s %d\n", label("Data components:"), len(components))
		fmt.Printf("%s %s\n", label("Description:"), d.Description)

		viewedAnalytics := false
		viewedTechniques := false
		viewedComponents := false

		for {
			fmt.Println("\nNext:")
			if !viewedTechniques {
				fmt.Println("  [1] View mapped techniques")
			}
			if !viewedAnalytics {
				fmt.Println("  [2] View analytics")
			}
			if !viewedComponents {
				fmt.Println("  [3] View data components")
			}
			fmt.Println("  [b] Back to detections")
			fmt.Println("  [q] Return to guided menu")
			fmt.Print("> ")

			next := strings.ToLower(readLine(reader))

			switch next {
			case "1":
				if viewedTechniques {
					fmt.Println("Invalid selection.")
					continue
				}
				if len(techniques) == 0 {
					fmt.Println("No mapped techniques for this detection strategy.")
				} else {
					printTechniqueTable(techniques)
				}
				viewedTechniques = true

			case "2":
				if viewedAnalytics {
					fmt.Println("Invalid selection.")
					continue
				}
				if len(analytics) == 0 {
					fmt.Println("No analytics mapped for this detection strategy.")
				} else {
					printAnalyticList(analytics)
				}
				viewedAnalytics = true

			case "3":
				if viewedComponents {
					fmt.Println("Invalid selection.")
					continue
				}
				if len(components) == 0 {
					fmt.Println("No data components mapped for this detection strategy.")
				} else {
					printDataComponentList(components)
				}
				viewedComponents = true
			case "b":
				fmt.Println()
				goto detectionList
			case "q":
				return
			default:
				fmt.Println("Invalid selection.")
			}
		}
	detectionList:
	}

}

func runGuidedAnalytics(cache CacheData, reader *bufio.Reader) {
	if len(cache.Analytics) == 0 {
		fmt.Println("No analytics found in cache.")
		return
	}

	analytics := make([]Analytic, len(cache.Analytics))
	copy(analytics, cache.Analytics)
	sort.Slice(analytics, func(i, j int) bool { return analytics[i].ID < analytics[j].ID })

	for {
		fmt.Println(title("Analytics"))
		fmt.Printf("%s %d analytic(s)\n", ok("Found"), len(analytics))
		fmt.Printf("%-4s %-12s %s\n", "#", "ID", "Name")
		fmt.Println(strings.Repeat("-", 76))

		for i, a := range analytics {
			fmt.Printf("%-4d %-12s %s\n", i+1, a.ID, truncateText(a.Name, 56))
		}

		fmt.Println("  [q] Return to guided menu")
		fmt.Print("> ")

		input := readLine(reader)
		if strings.EqualFold(input, "q") {
			return
		}

		idx, err := strconv.Atoi(input)
		if err != nil || idx < 1 || idx > len(analytics) {
			fmt.Println("Invalid selection.")
			continue
		}

		a := analytics[idx-1]
		components := dataComponentsByAnalytic(cache, a.ID)

		fmt.Println()
		fmt.Printf("%s %s\n", label("ID:"), a.ID)
		fmt.Printf("%s %s\n", label("Name:"), a.Name)
		fmt.Printf("%s %d\n", label("Data components:"), len(components))
		fmt.Printf("%s %s\n", label("Description:"), a.Description)

		viewedComponents := false

		for {
			fmt.Println("\nNext:")
			if !viewedComponents {
				fmt.Println("  [1] View data components")
			}
			fmt.Println("  [b] Back to analytics")
			fmt.Println("  [q] Return to guided menu")
			fmt.Print("> ")

			next := strings.ToLower(readLine(reader))

			switch next {
			case "1":
				if viewedComponents {
					fmt.Println("Invalid selection.")
					continue
				}
				if len(components) == 0 {
					fmt.Println("No data components mapped for this analytic.")
				} else {
					printDataComponentList(components)
				}
				viewedComponents = true
			case "b":
				fmt.Println()
				goto analyticList
			case "q":
				return
			default:
				fmt.Println("Invalid selection.")
			}
		}
	analyticList:
	}

}

func printAnalyticList(analytics []Analytic) {
	fmt.Printf("%-4s %-12s %s\n", "#", "ID", "Name")
	fmt.Println(strings.Repeat("-", 76))

	for i, a := range analytics {
		fmt.Printf("%-4d %-12s %s\n", i+1, a.ID, truncateText(a.Name, 56))
	}
}

func printDataComponentList(components []DataComponent) {
	fmt.Printf("%-4s %s\n", "#", "Name")
	fmt.Println(strings.Repeat("-", 64))

	for i, dc := range components {
		fmt.Printf("%-4d %s\n", i+1, truncateText(dc.Name, 56))
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
