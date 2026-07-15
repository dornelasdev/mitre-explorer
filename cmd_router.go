package main

import (
	"fmt"
)

func runCommand(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: go run . <command>")
		return
	}

	useColor = true

	if err := setActiveMatrix("enterprise"); err != nil {
		fmt.Println(errText(err.Error()))
		return
	}

	command := args[0]

	filtered := make([]string, 0, len(args))
	filtered = append(filtered, command)

	for i := 1; i < len(args); i++ {
		a := args[i]

		if a == "--plain" {
			useColor = false
			continue
		}

		if a == "--matrix" {
			if i+1 >= len(args) {
				fmt.Println("Usage: --matrix <enterprise|mobile|ics>")
				return
			}

			if err := setActiveMatrix(args[i+1]); err != nil {
				fmt.Println(errText(err.Error()))
				return
			}

			i++
			continue
		}

		filtered = append(filtered, a)
	}
	args = filtered

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
