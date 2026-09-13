package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

func startInteractiveMode() {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("Matrix: %s\n", activeMatrixName())
		fmt.Println("  [1] Guided Explorer")
		fmt.Println("  [2] Manual Command Mode")
		fmt.Println("  [q] Quit")
		fmt.Print("> ")

		choice, err := readLine(reader)
		if err != nil {
			return
		}

		switch strings.ToLower(choice) {
		case "1":
			fmt.Println("Guided Explorer mode selected.")
			runGuidedExplorer()

		case "2":
			fmt.Println("Manual mode selected.")
			fmt.Println("Type a command (without `go run .`), for example:")
			fmt.Println("  search powershell --limit 5 --detailed")
			fmt.Println("  show T1059")
			fmt.Println("  list techniques --tactic execution --plain")
			fmt.Println("Type `back` to return to mode menu, or `q` to quit.")

			for {
				fmt.Print("manual> ")
				line, err := readLine(reader)
				if err != nil {
					return
				}
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
				dispatchCommand(cmdArgs)
			}
		case "q":
			fmt.Println("Exiting.")
			return

		default:
			fmt.Println("Invalid choice.")
		}
	}
}

func readLine(reader *bufio.Reader) (string, error) {
	input, err := reader.ReadString('\n')
	// Process a final unterminated line before reporting EOF on the next read.
	if err == io.EOF && len(input) > 0 {
		err = nil
	}
	return strings.TrimSpace(input), err
}
