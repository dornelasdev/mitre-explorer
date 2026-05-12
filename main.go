package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	fmt.Println("MITRE Explorer v0.65")

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
		fmt.Println("MITRE EXPLORER V0.65")
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
	 techniques, err := loadTechniques(cachePath)
	 if err != nil {
		if os.IsNotExist(err) {
			fmt.Println(errText("Cache not found. Run: go run . update"))
			return
		}
		fmt.Printf("Error loading cache: %v\n", err)
		return
	 }

	 tactics := collectUniqueTactics(techniques)
	 if len(tactics) == 0 {
		fmt.Println("No tactics found in cache.")
		return
	 }

	 reader := bufio.NewReader(os.Stdin)

	 for {
		fmt.Println("Select a tactic (number), or 'q' to quit:")
		for i, t := range tactics {
			fmt.Printf("  [%d] %s\n", i+1, t)
		}
		fmt.Print("> ")

		tacticInput := readLine(reader)
		if strings.EqualFold(tacticInput, "q") {
			fmt.Println("Exiting guided explorer.")
			return
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
			fmt.Println("  [q] Exit guided mode")
			fmt.Print("> ")

			pickInput := readLine(reader)

			if strings.EqualFold(pickInput, "q") {
				fmt.Println("Exiting guided explorer.")
				return
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

			backToTactics := false

			for {
				fmt.Println("\nNext:")
				fmt.Println("  [1] Back to techniques")
				fmt.Println("  [2] Back to tactics")
				fmt.Println("  [q] Exit guided mode")
				fmt.Print("> ")

				nextInput := readLine(reader)

				switch nextInput {
				case "1":

				case "2":
					backToTactics = true
				case "q":
					fmt.Println("Exiting guided explorer.")
					return
				default:
					fmt.Println("Invalid selection.")
					continue
				}
				break
			}
			if backToTactics {
				break
			}
		}
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

		techniques, err := buildTechniquesFromSTIX(rawPath)
		if err != nil {
			fmt.Printf("Parse failed: %v\n", err)
			return
		}

		if err := saveTechniques(cachePath, techniques); err != nil {
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
		fmt.Printf("Parsed techniques: %d\n", len(techniques))
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
		techniques, err := loadTechniques(cachePath)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Println(errText("Cache not found. Run: go run . update"))
				return
			}
			fmt.Printf("Error loading cache: %v\n", err)
			return
		}

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
		if detailed {
			for i, r := range results {
				fmt.Printf("\n[%d] %s | %s\n", i+1, r.ID, r.Name)
				fmt.Printf("    Tactics: %s\n", strings.Join(r.Tactics, ", "))
				fmt.Printf("    Platforms: %s\n", strings.Join(r.Platforms, ", "))
			}
		} else {
			printTechniqueTable(results)
		}


	case "show":
		if len(args) < 2 {
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

		techniques, err := loadTechniques(cachePath)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Println(errText("Cache not found. Run: go run . update"))
				return
			}
			fmt.Printf("Error loading cache: %v\n", err)
			return
		}

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
		if detailed {
			for i, t := range results {
				fmt.Printf("\n[%d] %s | %s\n", i+1, t.ID, t.Name)
				fmt.Printf("    Tactics: %s\n", strings.Join(t.Tactics, ", "))
				fmt.Printf("    Platforms: %s\n", strings.Join(t.Platforms, ", "))
			}
		} else {
			printTechniqueTable(results)
		}

	default:
		fmt.Printf("Unknown command: %s\n", command)
	}
}

