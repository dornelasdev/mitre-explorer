package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func main() {
	fmt.Println("MITRE Explorer v0.7.8")

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
