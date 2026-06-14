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
				printNoResults("tactics")
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
					printInvalidSelection()
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
						printInvalidSelection()
						continue
					}

					selected := results[pick-1]
					printSection("Technique Details")
					printTechniqueDetails(selected)

					fmt.Println()
					fmt.Println("Press Enter to return to the technique list.")
					fmt.Print("> ")
					readLine(reader)

				}
			}
		case "2":
			if len(cache.Groups) == 0 {
				printNoResults("groups")
				continue
			}

			groups := make([]Group, len(cache.Groups))
			copy(groups, cache.Groups)
			sort.Slice(groups, func(i, j int) bool { return groups[i].ID < groups[j].ID })

			for {
				fmt.Println(title("Groups"))
				fmt.Printf("%s %d group(s)\n", ok("Found"), len(groups))
				printGroupTable(groups)
				fmt.Println("  [q] Return to guided menu")
				fmt.Print("> ")

				input := readLine(reader)
				if strings.EqualFold(input, "q") {
					break
				}

				idx, err := strconv.Atoi(input)
				if err != nil || idx < 1 || idx > len(groups) {
					printInvalidSelection()
					continue
				}

				g := groups[idx-1]
				related := techniquesUsedByGroup(cache, g.ID)

				printSection("Group Details")
				printDetails([]DetailField{
					{"ID:", g.ID},
					{"Name:", g.Name},
					{"Aliases:", strings.Join(g.Aliases, ", ")},
					{"Mapped techniques:", strconv.Itoa(len(related))},
					{"Description:", g.Description},
				})

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
							printInvalidSelection()
							continue
						}
						if len(related) == 0 {
							printNoMappedResults("techniques", "group")
						} else {
							printSubsection("Mapped Techniques")
							printTechniqueTable(related)
						}
						viewedMapped = true

					case "b":
						fmt.Println()
						goto groupList
					case "q":
						goto guidedMenu
					default:
						printInvalidSelection()
					}
				}
			groupList:
			}

		case "3":
			if len(cache.Mitigations) == 0 {
				printNoResults("mitigations")
				continue
			}

			mitigations := make([]Mitigation, len(cache.Mitigations))
			copy(mitigations, cache.Mitigations)
			sort.Slice(mitigations, func(i, j int) bool { return mitigations[i].ID < mitigations[j].ID })

			for {
				fmt.Println(title("Mitigations"))
				fmt.Printf("%s %d mitigation(s)\n", ok("Found"), len(mitigations))
				printMitigationTable(mitigations)
				fmt.Println("  [q] Return to guided menu")
				fmt.Print("> ")

				input := readLine(reader)
				if strings.EqualFold(input, "q") {
					break
				}

				idx, err := strconv.Atoi(input)
				if err != nil || idx < 1 || idx > len(mitigations) {
					printInvalidSelection()
					continue
				}

				m := mitigations[idx-1]
				related := techniquesMitigatedBy(cache, m.ID)

				printSection("Mitigation Details")
				printDetails([]DetailField{
					{"ID:", m.ID},
					{"Name:", m.Name},
					{"Mapped techniques:", strconv.Itoa(len(related))},
					{"Description:", m.Description},
				})

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
							printInvalidSelection()
							continue
						}
						if len(related) == 0 {
							printNoMappedResults("techniques", "mitigation")
						} else {
							printSubsection("Mapped techniques")
							printTechniqueTable(related)
						}
						viewedMapped = true

					case "b":
						fmt.Println()
						goto mitigationList
					case "q":
						goto guidedMenu
					default:
						printInvalidSelection()
					}
				}
			mitigationList:
			}
		case "4":
			if len(cache.Softwares) == 0 {
				printNoResults("softwares")
				continue
			}

			softwares := make([]Software, len(cache.Softwares))
			copy(softwares, cache.Softwares)
			sort.Slice(softwares, func(i, j int) bool { return softwares[i].ID < softwares[j].ID })
			for {
				fmt.Println(title("Software"))
				fmt.Printf("%s %d software item(s)\n", ok("Found"), len(softwares))
				printSoftwareTable(softwares)
				fmt.Println("  [q] Return to guided menu")
				fmt.Print("> ")

				input := readLine(reader)
				if strings.EqualFold(input, "q") {
					break
				}

				idx, err := strconv.Atoi(input)
				if err != nil || idx < 1 || idx > len(softwares) {
					printInvalidSelection()
					continue
				}

				s := softwares[idx-1]
				related := techniquesUsedBySoftware(cache, s.ID)

				printSection("Software Details")
				printDetails([]DetailField{
					{"ID:", s.ID},
					{"Name:", s.Name},
					{"Type:", s.Type},
					{"Aliases:", strings.Join(s.Aliases, ", ")},
					{"Mapped techniques:", strconv.Itoa(len(related))},
					{"Description:", s.Description},
				})

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
							printInvalidSelection()
							continue
						}
						if len(related) == 0 {
							printNoMappedResults("techniques", "software")
						} else {
							printSubsection("Mapped Techniques")
							printTechniqueTable(related)
						}
						viewedMapped = true

					case "b":
						fmt.Println()
						goto softwareList
					case "q":
						goto guidedMenu
					default:
						printInvalidSelection()
					}
				}
			softwareList:
			}
		case "5":
			if len(cache.Campaigns) == 0 {
				printNoResults("campaigns")
				continue
			}

			campaigns := make([]Campaign, len(cache.Campaigns))
			copy(campaigns, cache.Campaigns)
			sort.Slice(campaigns, func(i, j int) bool { return campaigns[i].ID < campaigns[j].ID })

			for {
				fmt.Println(title("Campaigns"))
				fmt.Printf("%s %d campaign(s)\n", ok("Found"), len(campaigns))
				printCampaignTable(campaigns)
				fmt.Println("  [q] Return to guided menu")
				fmt.Print("> ")

				input := readLine(reader)
				if strings.EqualFold(input, "q") {
					break
				}

				idx, err := strconv.Atoi(input)
				if err != nil || idx < 1 || idx > len(campaigns) {
					printInvalidSelection()
					continue
				}

				c := campaigns[idx-1]
				related := techniquesUsedByCampaign(cache, c.ID)

				printSection("Campaign Details")
				printDetails([]DetailField{
					{"ID:", c.ID},
					{"Name:", c.Name},
					{"Aliases:", strings.Join(c.Aliases, ", ")},
					{"Mapped techniques:", strconv.Itoa(len(related))},
					{"Description:", c.Description},
				})

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
							printInvalidSelection()
							continue
						}
						if len(related) == 0 {
							printNoMappedResults("techniques", "campaign")
						} else {
							printSubsection("Mapped Techniques")
							printTechniqueTable(related)
						}
						viewedMapped = true
					case "b":
						fmt.Println()
						goto campaignList
					case "q":
						goto guidedMenu
					default:
						printInvalidSelection()
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
			printInvalidSelection()
		}

	guidedMenu:
	}
}

func runGuidedDataComponents(cache CacheData, reader *bufio.Reader) {
	if len(cache.DataComponents) == 0 {
		printNoResults("data components")
		return
	}

	components := make([]DataComponent, len(cache.DataComponents))
	copy(components, cache.DataComponents)
	sort.Slice(components, func(i, j int) bool { return components[i].Name < components[j].Name })

	for {
		fmt.Println(title("Data Components"))
		fmt.Printf("%s %d data component(s)\n", ok("Found"), len(components))
		printDataComponentList(components)

		fmt.Println("  [q] Return to guided menu")
		fmt.Print("> ")

		input := readLine(reader)
		if strings.EqualFold(input, "q") {
			return
		}

		idx, err := strconv.Atoi(input)
		if err != nil || idx < 1 || idx > len(components) {
			printInvalidSelection()
			continue
		}

		dc := components[idx-1]
		related := techniquesByDataComponent(cache, dc.Name)

		printSection("Data Component Details")
		printDetails([]DetailField{
			{"Name:", dc.Name},
			{"Mapped techniques:", strconv.Itoa(len(related))},
			{"Description:", dc.Description},
		})

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
					printInvalidSelection()
					continue
				}
				if len(related) == 0 {
					printNoMappedResults("techniques", "data component")
				} else {
					printSubsection("Mapped Techniques")
					printTechniqueTable(related)
				}
				viewedMapped = true
			case "b":
				fmt.Println()
				goto componentList
			case "q":
				return
			default:
				printInvalidSelection()
			}
		}
	componentList:
	}

}

func runGuidedDetections(cache CacheData, reader *bufio.Reader) {
	if len(cache.DetectionStrategies) == 0 {
		printNoResults("detection strategies")
		return
	}

	detections := make([]DetectionStrategy, len(cache.DetectionStrategies))
	copy(detections, cache.DetectionStrategies)
	sort.Slice(detections, func(i, j int) bool { return detections[i].Name < detections[j].Name })

	for {
		fmt.Println(title("Detection Strategies"))
		fmt.Printf("%s %d detection strategy item(s)\n", ok("Found"), len(detections))
		printDetectionTable(detections)
		fmt.Println("  [q] Return to guided menu")
		fmt.Print("> ")

		input := readLine(reader)
		if strings.EqualFold(input, "q") {
			return
		}

		idx, err := strconv.Atoi(input)
		if err != nil || idx < 1 || idx > len(detections) {
			printInvalidSelection()
			continue
		}

		d := detections[idx-1]
		techniques := techniquesDetectedByStrategy(cache, d.ID)
		analytics := analyticsByDetectionStrategy(cache, d.ID)
		components := dataComponentsByDetectionStrategy(cache, d.ID)

		printSection("Detection Strategy Details")
		printDetails([]DetailField{
			{"ID:", d.ID},
			{"Name:", d.Name},
			{"Mapped techniques:", strconv.Itoa(len(techniques))},
			{"Analytics:", strconv.Itoa(len(analytics))},
			{"Data Components:", strconv.Itoa(len(components))},
			{"Description:", d.Description},
		})

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
					printInvalidSelection()
					continue
				}
				if len(techniques) == 0 {
					printNoMappedResults("techniques", "detection strategy")
				} else {
					printSubsection("Mapped Techniques")
					printTechniqueTable(techniques)
				}
				viewedTechniques = true

			case "2":
				if viewedAnalytics {
					printInvalidSelection()
					continue
				}
				if len(analytics) == 0 {
					printNoMappedResults("analytics", "detection strategy")
				} else {
					printSubsection("Mapped Analytics")
					printAnalyticList(analytics)
				}
				viewedAnalytics = true

			case "3":
				if viewedComponents {
					printInvalidSelection()
					continue
				}
				if len(components) == 0 {
					printNoMappedResults("data components", "detection strategy")
				} else {
					printSubsection("Mapped Data Components")
					printDataComponentList(components)
				}
				viewedComponents = true
			case "b":
				fmt.Println()
				goto detectionList
			case "q":
				return
			default:
				printInvalidSelection()
			}
		}
	detectionList:
	}

}

func runGuidedAnalytics(cache CacheData, reader *bufio.Reader) {
	if len(cache.Analytics) == 0 {
		printNoResults("analytics")
		return
	}

	analytics := make([]Analytic, len(cache.Analytics))
	copy(analytics, cache.Analytics)
	sort.Slice(analytics, func(i, j int) bool { return analytics[i].ID < analytics[j].ID })

	for {
		fmt.Println(title("Analytics"))
		fmt.Printf("%s %d analytic(s)\n", ok("Found"), len(analytics))
		printAnalyticList(analytics)

		fmt.Println("  [q] Return to guided menu")
		fmt.Print("> ")

		input := readLine(reader)
		if strings.EqualFold(input, "q") {
			return
		}

		idx, err := strconv.Atoi(input)
		if err != nil || idx < 1 || idx > len(analytics) {
			printInvalidSelection()
			continue
		}

		a := analytics[idx-1]
		components := dataComponentsByAnalytic(cache, a.ID)

		printSection("Analytic Details")
		printDetails([]DetailField{
			{"ID:", a.ID},
			{"Name:", a.Name},
			{"Data Components:", strconv.Itoa(len(components))},
			{"Description:", a.Description},
		})

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
					printInvalidSelection()
					continue
				}
				if len(components) == 0 {
					printNoMappedResults("data components", "analytic")
				} else {
					printSubsection("Mapped Data Components")
					printDataComponentList(components)
				}
				viewedComponents = true
			case "b":
				fmt.Println()
				goto analyticList
			case "q":
				return
			default:
				printInvalidSelection()
			}
		}
	analyticList:
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
