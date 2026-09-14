package cli

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"mitre-explorer/internal/attack"
)

func (app *App) runGuidedExplorer() {
	cache, err := attack.LoadCacheData(app.matrix.CachePath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(app.out, "%s\n", app.errText(fmt.Sprintf("Cache not found for matrix %q. Run: go run . update --matrix %s", app.activeMatrixName(), app.activeMatrixName())))
			return
		}
		fmt.Fprintf(app.out, "Error loading cache: %v\n", err)
		return
	}

	reader := app.reader

	for {
		fmt.Fprintln(app.out, "Guided Explorer")
		fmt.Fprintf(app.out, "%s %s\n", app.label("Matrix:"), app.activeMatrixName())
		fmt.Fprintln(app.out, "  [1] Explore Tactics")
		fmt.Fprintln(app.out, "  [2] Explore Groups")
		fmt.Fprintln(app.out, "  [3] Explore Mitigations")
		fmt.Fprintln(app.out, "  [4] Explore Software")
		fmt.Fprintln(app.out, "  [5] Explore Campaigns")
		fmt.Fprintln(app.out, "  [6] Explore Data Components")
		fmt.Fprintln(app.out, "  [7] Explore Detection Strategies")
		fmt.Fprintln(app.out, "  [8] Explore Analytics")
		fmt.Fprintln(app.out, "  [q] Exit guided mode")
		fmt.Fprintf(app.out, "> ")

		choice, err := readLine(reader)
		if err != nil {
			return
		}
		choice = strings.ToLower(choice)

		switch choice {
		case "1":
			techniques := cache.Techniques
			tactics := attack.CollectUniqueTactics(techniques, app.matrix.TacticOrder)
			if len(tactics) == 0 {
				app.printNoResults("tactics")
				continue
			}

			for {
				fmt.Fprintln(app.out, "Select a tactic (number), or 'q' to return:")
				for i, t := range tactics {
					fmt.Fprintf(app.out, "  [%d] %s\n", i+1, t)
				}
				fmt.Fprint(app.out, "> ")

				tacticInput, err := readLine(reader)
				if err != nil {
					return
				}
				if strings.EqualFold(tacticInput, "q") {
					break
				}

				tacticIndex, err := strconv.Atoi(tacticInput)
				if err != nil || tacticIndex < 1 || tacticIndex > len(tactics) {
					app.printInvalidSelection()
					continue
				}

				selectedTactic := tactics[tacticIndex-1]
				results := attack.ListByTactic(techniques, selectedTactic)
				if len(results) == 0 {
					fmt.Fprintln(app.out, "No techniques found for this tactic.")
					continue
				}

				for {
					fmt.Fprintln(app.out, app.title("Techniques"))
					fmt.Fprintf(app.out, "%s %q (%d)\n", app.ok("Tactic:"), selectedTactic, len(results))
					app.printTechniqueTable(results)
					fmt.Fprintln(app.out, "  [b] Back to tactics")
					fmt.Fprintln(app.out, "  [q] Return to guided menu")
					fmt.Fprint(app.out, "> ")

					pickInput, err := readLine(reader)
					if err != nil {
						return
					}

					if strings.EqualFold(pickInput, "q") {
						goto guidedMenu
					}
					if strings.EqualFold(pickInput, "b") {
						break
					}

					pick, err := strconv.Atoi(pickInput)
					if err != nil || pick < 1 || pick > len(results) {
						app.printInvalidSelection()
						continue
					}

					selected := results[pick-1]
					app.printSection("Technique Details")
					app.printTechniqueDetails(selected)

					fmt.Fprintln(app.out)
					fmt.Fprintln(app.out, "Press Enter to return to the technique list.")
					fmt.Fprint(app.out, "> ")
					if _, err := readLine(reader); err != nil {
						return
					}

				}
			}
		case "2":
			if len(cache.Groups) == 0 {
				app.printNoResults("groups")
				continue
			}

			groups := make([]attack.Group, len(cache.Groups))
			copy(groups, cache.Groups)
			sort.Slice(groups, func(i, j int) bool { return groups[i].ID < groups[j].ID })

			for {
				fmt.Fprintln(app.out, app.title("Groups"))
				fmt.Fprintf(app.out, "%s %d group(s)\n", app.ok("Found"), len(groups))
				app.printGroupTable(groups)
				fmt.Fprintln(app.out, "  [q] Return to guided menu")
				fmt.Fprint(app.out, "> ")

				input, err := readLine(reader)
				if err != nil {
					return
				}
				if strings.EqualFold(input, "q") {
					break
				}

				idx, err := strconv.Atoi(input)
				if err != nil || idx < 1 || idx > len(groups) {
					app.printInvalidSelection()
					continue
				}

				g := groups[idx-1]
				related := attack.TechniquesUsedByGroup(cache, g.ID)

				app.printSection("Group Details")
				app.printDetails([]DetailField{
					{"ID:", g.ID},
					{"Name:", g.Name},
					{"Aliases:", strings.Join(g.Aliases, ", ")},
					{"Mapped techniques:", strconv.Itoa(len(related))},
					{"Description:", g.Description},
				})

				viewedMapped := false

				for {
					fmt.Fprintln(app.out, "\nNext:")
					if !viewedMapped {
						fmt.Fprintln(app.out, "  [1] View mapped techniques")
					}
					fmt.Fprintln(app.out, "  [b] Back to groups")
					fmt.Fprintln(app.out, "  [q] Return to guided menu")
					fmt.Fprint(app.out, "> ")

					next, err := readLine(reader)
					if err != nil {
						return
					}
					next = strings.ToLower(next)
					switch next {
					case "1":
						if viewedMapped {
							app.printInvalidSelection()
							continue
						}
						if len(related) == 0 {
							app.printNoMappedResults("techniques", "group")
						} else {
							app.printSubsection("Mapped Techniques")
							app.printTechniqueTable(related)
						}
						viewedMapped = true

					case "b":
						fmt.Fprintln(app.out)
						goto groupList
					case "q":
						goto guidedMenu
					default:
						app.printInvalidSelection()
					}
				}
			groupList:
			}

		case "3":
			if len(cache.Mitigations) == 0 {
				app.printNoResults("mitigations")
				continue
			}

			mitigations := make([]attack.Mitigation, len(cache.Mitigations))
			copy(mitigations, cache.Mitigations)
			sort.Slice(mitigations, func(i, j int) bool { return mitigations[i].ID < mitigations[j].ID })

			for {
				fmt.Fprintln(app.out, app.title("Mitigations"))
				fmt.Fprintf(app.out, "%s %d mitigation(s)\n", app.ok("Found"), len(mitigations))
				app.printMitigationTable(mitigations)
				fmt.Fprintln(app.out, "  [q] Return to guided menu")
				fmt.Fprint(app.out, "> ")

				input, err := readLine(reader)
				if err != nil {
					return
				}
				if strings.EqualFold(input, "q") {
					break
				}

				idx, err := strconv.Atoi(input)
				if err != nil || idx < 1 || idx > len(mitigations) {
					app.printInvalidSelection()
					continue
				}

				m := mitigations[idx-1]
				related := attack.TechniquesMitigatedBy(cache, m.ID)

				app.printSection("Mitigation Details")
				app.printDetails([]DetailField{
					{"ID:", m.ID},
					{"Name:", m.Name},
					{"Mapped techniques:", strconv.Itoa(len(related))},
					{"Description:", m.Description},
				})

				viewedMapped := false

				for {
					fmt.Fprintln(app.out, "\nNext:")
					if !viewedMapped {
						fmt.Fprintln(app.out, "  [1] View mapped techniques")
					}
					fmt.Fprintln(app.out, "  [b] Back to mitigations")
					fmt.Fprintln(app.out, "  [q] Return to guided menu")
					fmt.Fprint(app.out, "> ")

					next, err := readLine(reader)
					if err != nil {
						return
					}
					next = strings.ToLower(next)
					switch next {
					case "1":
						if viewedMapped {
							app.printInvalidSelection()
							continue
						}
						if len(related) == 0 {
							app.printNoMappedResults("techniques", "mitigation")
						} else {
							app.printSubsection("Mapped techniques")
							app.printTechniqueTable(related)
						}
						viewedMapped = true

					case "b":
						fmt.Fprintln(app.out)
						goto mitigationList
					case "q":
						goto guidedMenu
					default:
						app.printInvalidSelection()
					}
				}
			mitigationList:
			}
		case "4":
			if len(cache.Softwares) == 0 {
				app.printNoResults("softwares")
				continue
			}

			softwares := make([]attack.Software, len(cache.Softwares))
			copy(softwares, cache.Softwares)
			sort.Slice(softwares, func(i, j int) bool { return softwares[i].ID < softwares[j].ID })
			for {
				fmt.Fprintln(app.out, app.title("Software"))
				fmt.Fprintf(app.out, "%s %d software item(s)\n", app.ok("Found"), len(softwares))
				app.printSoftwareTable(softwares)
				fmt.Fprintln(app.out, "  [q] Return to guided menu")
				fmt.Fprint(app.out, "> ")

				input, err := readLine(reader)
				if err != nil {
					return
				}
				if strings.EqualFold(input, "q") {
					break
				}

				idx, err := strconv.Atoi(input)
				if err != nil || idx < 1 || idx > len(softwares) {
					app.printInvalidSelection()
					continue
				}

				s := softwares[idx-1]
				related := attack.TechniquesUsedBySoftware(cache, s.ID)

				app.printSection("Software Details")
				app.printDetails([]DetailField{
					{"ID:", s.ID},
					{"Name:", s.Name},
					{"Type:", s.Type},
					{"Aliases:", strings.Join(s.Aliases, ", ")},
					{"Mapped techniques:", strconv.Itoa(len(related))},
					{"Description:", s.Description},
				})

				viewedMapped := false
				for {
					fmt.Fprintln(app.out, "\nNext:")
					if !viewedMapped {
						fmt.Fprintln(app.out, "  [1] View mapped techniques")
					}
					fmt.Fprintln(app.out, "  [b] Back to software list")
					fmt.Fprintln(app.out, "  [q] Return to guided menu")
					fmt.Fprint(app.out, "> ")

					next, err := readLine(reader)
					if err != nil {
						return
					}
					next = strings.ToLower(next)
					switch next {
					case "1":
						if viewedMapped {
							app.printInvalidSelection()
							continue
						}
						if len(related) == 0 {
							app.printNoMappedResults("techniques", "software")
						} else {
							app.printSubsection("Mapped Techniques")
							app.printTechniqueTable(related)
						}
						viewedMapped = true

					case "b":
						fmt.Fprintln(app.out)
						goto softwareList
					case "q":
						goto guidedMenu
					default:
						app.printInvalidSelection()
					}
				}
			softwareList:
			}
		case "5":
			if len(cache.Campaigns) == 0 {
				app.printNoResults("campaigns")
				continue
			}

			campaigns := make([]attack.Campaign, len(cache.Campaigns))
			copy(campaigns, cache.Campaigns)
			sort.Slice(campaigns, func(i, j int) bool { return campaigns[i].ID < campaigns[j].ID })

			for {
				fmt.Fprintln(app.out, app.title("Campaigns"))
				fmt.Fprintf(app.out, "%s %d campaign(s)\n", app.ok("Found"), len(campaigns))
				app.printCampaignTable(campaigns)
				fmt.Fprintln(app.out, "  [q] Return to guided menu")
				fmt.Fprint(app.out, "> ")

				input, err := readLine(reader)
				if err != nil {
					return
				}
				if strings.EqualFold(input, "q") {
					break
				}

				idx, err := strconv.Atoi(input)
				if err != nil || idx < 1 || idx > len(campaigns) {
					app.printInvalidSelection()
					continue
				}

				c := campaigns[idx-1]
				related := attack.TechniquesUsedByCampaign(cache, c.ID)

				app.printSection("Campaign Details")
				app.printDetails([]DetailField{
					{"ID:", c.ID},
					{"Name:", c.Name},
					{"Aliases:", strings.Join(c.Aliases, ", ")},
					{"Mapped techniques:", strconv.Itoa(len(related))},
					{"Description:", c.Description},
				})

				viewedMapped := false
				for {
					fmt.Fprintln(app.out, "\nNext:")
					if !viewedMapped {
						fmt.Fprintln(app.out, "  [1] View mapped techniques")
					}
					fmt.Fprintln(app.out, "  [b] Back to campaigns")
					fmt.Fprintln(app.out, "  [q] Return to guided menu")
					fmt.Fprint(app.out, "> ")

					next, err := readLine(reader)
					if err != nil {
						return
					}
					next = strings.ToLower(next)
					switch next {
					case "1":
						if viewedMapped {
							app.printInvalidSelection()
							continue
						}
						if len(related) == 0 {
							app.printNoMappedResults("techniques", "campaign")
						} else {
							app.printSubsection("Mapped Techniques")
							app.printTechniqueTable(related)
						}
						viewedMapped = true
					case "b":
						fmt.Fprintln(app.out)
						goto campaignList
					case "q":
						goto guidedMenu
					default:
						app.printInvalidSelection()
					}
				}
			campaignList:
			}
		case "6":
			app.runGuidedDataComponents(cache)

		case "7":
			app.runGuidedDetections(cache)

		case "8":
			app.runGuidedAnalytics(cache)

		case "q":
			fmt.Fprintln(app.out, "Exiting guided explorer.")
			return
		default:
			app.printInvalidSelection()
		}

	guidedMenu:
	}
}

func (app *App) runGuidedDataComponents(cache attack.CacheData) {
	reader := app.reader
	if len(cache.DataComponents) == 0 {
		app.printNoResults("data components")
		return
	}

	components := make([]attack.DataComponent, len(cache.DataComponents))
	copy(components, cache.DataComponents)
	sort.Slice(components, func(i, j int) bool { return components[i].Name < components[j].Name })

	for {
		fmt.Fprintln(app.out, app.title("Data Components"))
		fmt.Fprintf(app.out, "%s %d data component(s)\n", app.ok("Found"), len(components))
		app.printDataComponentList(components)

		fmt.Fprintln(app.out, "  [q] Return to guided menu")
		fmt.Fprint(app.out, "> ")

		input, err := readLine(reader)
		if err != nil {
			return
		}
		if strings.EqualFold(input, "q") {
			return
		}

		idx, err := strconv.Atoi(input)
		if err != nil || idx < 1 || idx > len(components) {
			app.printInvalidSelection()
			continue
		}

		dc := components[idx-1]
		componentID := dc.ID
		if componentID == "" {
			componentID = dc.StixID
		}
		related := attack.TechniquesByDataComponent(cache, componentID)

		app.printSection("Data Component Details")
		app.printDetails([]DetailField{
			{"Name:", dc.Name},
			{"Mapped techniques:", strconv.Itoa(len(related))},
			{"Description:", dc.Description},
		})

		viewedMapped := false

		for {
			fmt.Fprintln(app.out, "\nNext:")
			if !viewedMapped {
				fmt.Fprintln(app.out, "  [1] View mapped techniques")
			}
			fmt.Fprintln(app.out, "  [b] Back to data components")
			fmt.Fprintln(app.out, "  [q] Return to guided menu")
			fmt.Fprint(app.out, "> ")

			next, err := readLine(reader)
			if err != nil {
				return
			}
			next = strings.ToLower(next)

			switch next {
			case "1":
				if viewedMapped {
					app.printInvalidSelection()
					continue
				}
				if len(related) == 0 {
					app.printNoMappedResults("techniques", "data component")
				} else {
					app.printSubsection("Mapped Techniques")
					app.printTechniqueTable(related)
				}
				viewedMapped = true
			case "b":
				fmt.Fprintln(app.out)
				goto componentList
			case "q":
				return
			default:
				app.printInvalidSelection()
			}
		}
	componentList:
	}

}

func (app *App) runGuidedDetections(cache attack.CacheData) {
	reader := app.reader
	if len(cache.DetectionStrategies) == 0 {
		app.printNoResults("detection strategies")
		return
	}

	detections := make([]attack.DetectionStrategy, len(cache.DetectionStrategies))
	copy(detections, cache.DetectionStrategies)
	sort.Slice(detections, func(i, j int) bool { return detections[i].Name < detections[j].Name })

	for {
		fmt.Fprintln(app.out, app.title("Detection Strategies"))
		fmt.Fprintf(app.out, "%s %d detection strategy item(s)\n", app.ok("Found"), len(detections))
		app.printDetectionTable(detections)
		fmt.Fprintln(app.out, "  [q] Return to guided menu")
		fmt.Fprint(app.out, "> ")

		input, err := readLine(reader)
		if err != nil {
			return
		}
		if strings.EqualFold(input, "q") {
			return
		}

		idx, err := strconv.Atoi(input)
		if err != nil || idx < 1 || idx > len(detections) {
			app.printInvalidSelection()
			continue
		}

		d := detections[idx-1]
		techniques := attack.TechniquesDetectedByStrategy(cache, d.ID)
		analytics := attack.AnalyticsByDetectionStrategy(cache, d.ID)
		components := attack.DataComponentsByDetectionStrategy(cache, d.ID)

		app.printSection("Detection Strategy Details")
		app.printDetails([]DetailField{
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
			fmt.Fprintln(app.out, "\nNext:")
			if !viewedTechniques {
				fmt.Fprintln(app.out, "  [1] View mapped techniques")
			}
			if !viewedAnalytics {
				fmt.Fprintln(app.out, "  [2] View analytics")
			}
			if !viewedComponents {
				fmt.Fprintln(app.out, "  [3] View data components")
			}
			fmt.Fprintln(app.out, "  [b] Back to detections")
			fmt.Fprintln(app.out, "  [q] Return to guided menu")
			fmt.Fprint(app.out, "> ")

			next, err := readLine(reader)
			if err != nil {
				return
			}
			next = strings.ToLower(next)

			switch next {
			case "1":
				if viewedTechniques {
					app.printInvalidSelection()
					continue
				}
				if len(techniques) == 0 {
					app.printNoMappedResults("techniques", "detection strategy")
				} else {
					app.printSubsection("Mapped Techniques")
					app.printTechniqueTable(techniques)
				}
				viewedTechniques = true

			case "2":
				if viewedAnalytics {
					app.printInvalidSelection()
					continue
				}
				if len(analytics) == 0 {
					app.printNoMappedResults("analytics", "detection strategy")
				} else {
					app.printSubsection("Mapped Analytics")
					app.printAnalyticList(analytics)
				}
				viewedAnalytics = true

			case "3":
				if viewedComponents {
					app.printInvalidSelection()
					continue
				}
				if len(components) == 0 {
					app.printNoMappedResults("data components", "detection strategy")
				} else {
					app.printSubsection("Mapped Data Components")
					app.printDataComponentList(components)
				}
				viewedComponents = true
			case "b":
				fmt.Fprintln(app.out)
				goto detectionList
			case "q":
				return
			default:
				app.printInvalidSelection()
			}
		}
	detectionList:
	}

}

func (app *App) runGuidedAnalytics(cache attack.CacheData) {
	reader := app.reader
	if len(cache.Analytics) == 0 {
		app.printNoResults("analytics")
		return
	}

	analytics := make([]attack.Analytic, len(cache.Analytics))
	copy(analytics, cache.Analytics)
	sort.Slice(analytics, func(i, j int) bool { return analytics[i].ID < analytics[j].ID })

	for {
		fmt.Fprintln(app.out, app.title("Analytics"))
		fmt.Fprintf(app.out, "%s %d analytic(s)\n", app.ok("Found"), len(analytics))
		app.printAnalyticList(analytics)

		fmt.Fprintln(app.out, "  [q] Return to guided menu")
		fmt.Fprint(app.out, "> ")

		input, err := readLine(reader)
		if err != nil {
			return
		}
		if strings.EqualFold(input, "q") {
			return
		}

		idx, err := strconv.Atoi(input)
		if err != nil || idx < 1 || idx > len(analytics) {
			app.printInvalidSelection()
			continue
		}

		a := analytics[idx-1]
		components := attack.DataComponentsByAnalytic(cache, a.ID)

		app.printSection("Analytic Details")
		app.printDetails([]DetailField{
			{"ID:", a.ID},
			{"Name:", a.Name},
			{"Data Components:", strconv.Itoa(len(components))},
			{"Description:", a.Description},
		})

		viewedComponents := false

		for {
			fmt.Fprintln(app.out, "\nNext:")
			if !viewedComponents {
				fmt.Fprintln(app.out, "  [1] View data components")
			}
			fmt.Fprintln(app.out, "  [b] Back to analytics")
			fmt.Fprintln(app.out, "  [q] Return to guided menu")
			fmt.Fprint(app.out, "> ")

			next, err := readLine(reader)
			if err != nil {
				return
			}
			next = strings.ToLower(next)

			switch next {
			case "1":
				if viewedComponents {
					app.printInvalidSelection()
					continue
				}
				if len(components) == 0 {
					app.printNoMappedResults("data components", "analytic")
				} else {
					app.printSubsection("Mapped Data Components")
					app.printDataComponentList(components)
				}
				viewedComponents = true
			case "b":
				fmt.Fprintln(app.out)
				goto analyticList
			case "q":
				return
			default:
				app.printInvalidSelection()
			}
		}
	analyticList:
	}

}

func (app *App) printTechniqueDetails(t attack.Technique) {
	fmt.Fprintf(app.out, "ID: %s\n", t.ID)
	fmt.Fprintf(app.out, "Name: %s\n", t.Name)
	fmt.Fprintf(app.out, "Description: %s\n", t.Description)
	fmt.Fprintf(app.out, "Tactics: %s\n", strings.Join(t.Tactics, ", "))
	fmt.Fprintf(app.out, "Platforms: %s\n", strings.Join(t.Platforms, ", "))
	fmt.Fprintf(app.out, "Data Sources: %s\n", strings.Join(t.DataSources, ", "))
	fmt.Fprintf(app.out, "Detection Notes: %s\n", t.DetectionNotes)
}
