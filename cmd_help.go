package main

import "fmt"

func handleHelp(args []string) {
	if len(args) < 2 {
		printGlobalHelp()
		return
	}

	switch args[1] {
	case "update":
		printUpdateHelp()
	case "search":
		printSearchHelp()
	case "show":
		printShowHelp()
	case "list":
		printListHelp()
	case "group":
		printEntityHelp("group", "group_id_or_name", true, false, false)
	case "mitigation":
		printEntityHelp("mitigation", "mitigation_id_or_name", true, false, false)
	case "software":
		printEntityHelp("software", "software_id_or_name", true, false, false)
	case "campaign":
		printEntityHelp("campaign", "campaign_id_or_name", true, false, false)
	case "detection":
		printEntityHelp("detection", "detection_id_or_name", true, true, true)
	case "analytic":
		printEntityHelp("analytic", "analytic_id_or_name", false, false, true)
	default:
		fmt.Printf("Unknown help target: %s\n", args[1])
		fmt.Println("Use: go run . help")
	}
}

func printGlobalHelp() {
	fmt.Println("Usage: go run . <command> [arguments] [options]")
	fmt.Println()
	fmt.Println("Core commands:")
	fmt.Println("  update      Download/update local cache")
	fmt.Println("  search      Search techniques")
	fmt.Println("  show        Show technique details")
	fmt.Println("  list        List targets with pagination")
	fmt.Println()
	fmt.Println("Entity commands:")
	fmt.Println("  group        Show group details")
	fmt.Println("  mitigation   Show mitigation details")
	fmt.Println("  software     Show software details")
	fmt.Println("  campaign     Show campaign details")
	fmt.Println("  detection    Show detection details")
	fmt.Println("  analytic     Show analytic details")
	fmt.Println()
	fmt.Println("Use: go run . help <command>")
}

func printUpdateHelp() {
	fmt.Println("Usage: go run . update [-f|--force]")
	fmt.Println()
	fmt.Println("Downloads and normalizes the ATT&CK dataset into the local cache.")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  -f, --force    Force dataset download and cache rebuild")
}

func printSearchHelp() {
	fmt.Println("Usage: go run . search <term> [options]")
	fmt.Println()
	fmt.Println("Searches techniques by name/description, with optional detection-note searching.")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --name-only    	Search technique names only")
	fmt.Println("  --limit <N>    	Limit results to N techniques")
	fmt.Println("  --in-detection 	Show techniques with matching detection strategies")
	fmt.Println("  --plain        	Disable colored output")
	fmt.Println("  --detailed     	Show detailed technique output")
}

func printShowHelp() {
	fmt.Println("Usage:")
	fmt.Println("  go run . show <technique_id>")
	fmt.Println("  go run . show detection <technique_id>")
	fmt.Println()
	fmt.Println("Shows technique details or detection notes for a technique.")
}

func printListHelp() {
	fmt.Println("Usage: go run . list <target>")
	fmt.Println()
	fmt.Println("Targets:")
	fmt.Println("  techniques")
	fmt.Println("  groups")
	fmt.Println("  mitigations")
	fmt.Println("  software")
	fmt.Println("  campaigns")
	fmt.Println("  detections")
	fmt.Println("  analytics")
	fmt.Println("  data-components")
	fmt.Println("  tactics")
	fmt.Println("  platforms")
	fmt.Println()
	fmt.Println("Lists supported targets with pagination.")
}

func printEntityHelp(entity, idName string, supportsTechniques, supportsAnalytics, supportsComponents bool) {
	fmt.Printf("Usage: go run . %s <%s> [flags]\n", entity, idName)
	fmt.Println()
	fmt.Printf("Shows %s details", entity)

	if supportsTechniques || supportsAnalytics || supportsComponents {
		fmt.Print(" and optionally expands mapped relationships")
	}

	fmt.Println(".")
	fmt.Println()
	fmt.Println("Flags:")

	if supportsTechniques {
		fmt.Println("  -t, --techniques  Show mapped techniques")
		fmt.Println("  -d, --detailed    Show detailed output")
	}
	if supportsAnalytics {
		fmt.Println("  -a, --analytics   Show mapped analytics")
	}
	if supportsComponents {
		fmt.Println("  -c, --components  Show mapped data components")
	}

	fmt.Println("  --plain           Disable colored output")
}