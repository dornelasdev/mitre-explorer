package main

import (
	"fmt"
)

func applyGlobalOptions(args []string) ([]string, bool) {
	useColor = true
	if err := setActiveMatrix("enterprise"); err != nil {
		fmt.Println(errText(err.Error()))
		return nil, false
	}

	filtered := make([]string, 0, len(args))
	
	for i := 0; i < len(args); i++ {
		a := args[i]

		if a == "--plain" {
			useColor = false
			continue
		}

		if a == "--matrix" {
			if i+1 >= len(args) {
				fmt.Println("Usage: --matrix <enterprise|mobile|ics>")
				return nil, false
			}

			if err := setActiveMatrix(args[i+1]); err != nil {
				fmt.Println(errText(err.Error()))
				return nil, false
			}

			i++
			continue
		}

		filtered = append(filtered, a)
	}
	return filtered, true
}

func runCommand(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: go run . <command>")
		return
	}

	args, ok := applyGlobalOptions(args)
	if !ok {
		return
	}

	if len(args) == 0 {
		return
	}

	dispatchCommand(args)
}

func dispatchCommand(args []string) {
	command := args[0]

	switch command {
	case "update":
		handleUpdate(args)

	case "status":
		handleStatus(args)

	case "export":
		handleExport(args)

	case "help":
		handleHelp(args)

	case "search":
		handleSearch(args)
	case "show":
		handleShow(args)
	case "list":
		handleList(args)

	case "group":
		handleGroup(args)
	case "mitigation":
		handleMitigation(args)
	case "software":
		handleSoftware(args)
	case "campaign":
		handleCampaign(args)
	case "detection":
		handleDetection(args)
	case "analytic":
		handleAnalytic(args)

	default:
		fmt.Printf("Unknown command: %s\n", command)
	}
}
