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
