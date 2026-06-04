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
		handleUpdate(args)

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

	default:
		fmt.Printf("Unknown command: %s\n", command)
	}
}
