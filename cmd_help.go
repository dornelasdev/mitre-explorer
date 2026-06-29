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
	case "status":
		printStatusHelp()
	case "export":
		printExportHelp()
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
	fmt.Println("  status      Show cache and dataset status")
	fmt.Println("  search      Search techniques")
	fmt.Println("  show        Show technique details")
	fmt.Println("  list        List targets with pagination")
	fmt.Println("  export      Export cache data as CSV or Markdown")
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
	fmt.Println("Searches techniques by default. Use --target to search other entities.")
	fmt.Println()
	fmt.Println("Targets:")
	fmt.Println("  techniques, groups, mitigations, software, campaigns, detections, analytics, data-components, all")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --target <target>  Search a specific target")
	fmt.Println("  --name-only        Search technique names only")
	fmt.Println("  --limit <N>        Limit returned results")
	fmt.Println("  --in-detection     Show techniques with matching detection strategies")
	fmt.Println("  --plain            Disable colored output")
	fmt.Println("  --detailed         Show detailed technique output")
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
	fmt.Println("  techniques (aliases: tech, techs)")
	fmt.Println("  groups")
	fmt.Println("  mitigations")
	fmt.Println("  software")
	fmt.Println("  campaigns")
	fmt.Println("  detections (aliases: det, dets)")
	fmt.Println("  analytics")
	fmt.Println("  data-components (aliases: dc, dcs)")
	fmt.Println("  tactics")
	fmt.Println("  platforms")
	fmt.Println()
	fmt.Println("Lists supported targets with pagination.")
	fmt.Println()
	fmt.Println("Technique filters:")
	fmt.Println("  go run . list techniques --tactic <tactic_name>")
	fmt.Println("  go run . list techniques --platform <platform_name>")
	fmt.Println("  go run . list techniques --data-component <data_component_name>")
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

func printStatusHelp() {
	fmt.Println("Usage: go run . status")
	fmt.Println()
	fmt.Println("Shows the status of the local cache and update metadata.")
}

func printExportHelp() {
	fmt.Println("Usage: go run . export <target> --format csv|md --out <file>")
	fmt.Println()
	fmt.Println("Exports cached data into a basic report file.")
	fmt.Println()
	fmt.Println("Targets:")
	fmt.Println("  summary")
	fmt.Println("  techniques")
	fmt.Println("  groups")
	fmt.Println("  mitigations")
	fmt.Println("  software")
	fmt.Println("  campaigns")
	fmt.Println("  detections")
	fmt.Println("  analytics")
	fmt.Println("  data-components")
	fmt.Println()
	fmt.Println("Mapped relationships targets:")
	fmt.Println("  group-techniques")
	fmt.Println("  mitigation-techniques")
	fmt.Println("  software-techniques")
	fmt.Println("  campaign-techniques")
	fmt.Println("  detection-techniques")
	fmt.Println("  detection-analytics")
	fmt.Println("  detection-components")
	fmt.Println("  analytic-components")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  go run . export summary --format md --out reports/summary.md")
	fmt.Println("  go run . export techniques --format csv --out reports/techniques.csv")
	fmt.Println("  go run . export group-techniques --for <group_id_or_name> --format md --out reports/group-techniques.md")
}