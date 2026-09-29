package cli

import "fmt"

func (app *App) handleHelp(args []string) error {
	if len(args) > 2 {
		return invalidUsage("help accepts at most one command name")
	}
	if len(args) < 2 {
		app.printGlobalHelp()
		return nil
	}

	switch args[1] {
	case "update":
		app.printUpdateHelp()
	case "search":
		app.printSearchHelp()
	case "status":
		app.printStatusHelp()
	case "export":
		app.printExportHelp()
	case "tui":
		app.printTUIHelp()
	case "show":
		app.printShowHelp()
	case "list":
		app.printListHelp()
	case "group":
		app.printEntityHelp("group", "group_id_or_name", true, false, false)
	case "mitigation":
		app.printEntityHelp("mitigation", "mitigation_id_or_name", true, false, false)
	case "software":
		app.printEntityHelp("software", "software_id_or_name", true, false, false)
	case "campaign":
		app.printEntityHelp("campaign", "campaign_id_or_name", true, false, false)
	case "detection":
		app.printEntityHelp("detection", "detection_id_or_name", true, true, true)
	case "analytic":
		app.printEntityHelp("analytic", "analytic_id_or_name", false, false, true)
	default:
		return invalidUsage("unknown help target: %s", args[1])
	}
	return nil
}

func (app *App) printGlobalHelp() {
	fmt.Fprintln(app.out, "Usage: go run . <command> [arguments] [options]")
	fmt.Fprintln(app.out)
	fmt.Fprintln(app.out, "Core commands:")
	fmt.Fprintln(app.out, "  update      Download/update local cache")
	fmt.Fprintln(app.out, "  status      Show cache and dataset status")
	fmt.Fprintln(app.out, "  search      Search techniques and cached entities")
	fmt.Fprintln(app.out, "  show        Show technique details")
	fmt.Fprintln(app.out, "  list        List targets with pagination")
	fmt.Fprintln(app.out, "  export      Export cache data as CSV or Markdown")
	fmt.Fprintln(app.out, "  tui         Open the full-screen terminal interface")
	fmt.Fprintln(app.out)
	fmt.Fprintln(app.out, "Entity commands:")
	fmt.Fprintln(app.out, "  group        Show group details")
	fmt.Fprintln(app.out, "  mitigation   Show mitigation details")
	fmt.Fprintln(app.out, "  software     Show software details")
	fmt.Fprintln(app.out, "  campaign     Show campaign details")
	fmt.Fprintln(app.out, "  detection    Show detection details")
	fmt.Fprintln(app.out, "  analytic     Show analytic details")
	fmt.Fprintln(app.out)
	fmt.Fprintln(app.out, "Use: go run . help <command>")
	fmt.Fprintln(app.out)
	fmt.Fprintln(app.out, "Global options:")
	fmt.Fprintln(app.out, "  --matrix <matrix>    Select ATT&CK matrix: enterprise, mobile, or ics")
	fmt.Fprintln(app.out, "  --plain              Disable colored output")
	fmt.Fprintln(app.out)
	fmt.Fprintln(app.out, "Exit codes: 0 success, 1 operation failed, 2 invalid usage")
}

func (app *App) printUpdateHelp() {
	fmt.Fprintln(app.out, "Usage: go run . update [-f|--force] [--matrix enterprise|mobile|ics] [--plain]")
	fmt.Fprintln(app.out)
	fmt.Fprintln(app.out, "Downloads and normalizes the ATT&CK dataset into the local cache.")
	fmt.Fprintln(app.out)
	fmt.Fprintln(app.out, "Flags:")
	fmt.Fprintln(app.out, "  -f, --force          Force dataset download and cache rebuild")
	fmt.Fprintln(app.out, "  --matrix <matrix>    Select ATT&CK matrix source: enterprise, mobile, or ics")
	fmt.Fprintln(app.out, "  --plain              Disable colored output")
}

func (app *App) printSearchHelp() {
	fmt.Fprintln(app.out, "Usage: go run . search <term> [options]")
	fmt.Fprintln(app.out)
	fmt.Fprintln(app.out, "Searches techniques by default. Use --target to search other entities.")
	fmt.Fprintln(app.out)
	fmt.Fprintln(app.out, "Targets:")
	fmt.Fprintln(app.out, "  techniques, groups, mitigations, software, campaigns, detections, analytics, data-components, all")
	fmt.Fprintln(app.out)
	fmt.Fprintln(app.out, "Options:")
	fmt.Fprintln(app.out, "  --target <target>  Search a specific target")
	fmt.Fprintln(app.out, "  --name-only        Search technique names only")
	fmt.Fprintln(app.out, "  --limit <N>        Limit returned results")
	fmt.Fprintln(app.out, "  --in-detection     Search technique detection notes")
	fmt.Fprintln(app.out, "  --plain            Disable colored output")
	fmt.Fprintln(app.out, "  --detailed         Show detailed technique output")
	fmt.Fprintln(app.out, "  --matrix <matrix>  Select ATT&CK matrix")
}

func (app *App) printShowHelp() {
	fmt.Fprintln(app.out, "Usage:")
	fmt.Fprintln(app.out, "  go run . show <technique_id>")
	fmt.Fprintln(app.out, "  go run . show detection <technique_id>")
	fmt.Fprintln(app.out)
	fmt.Fprintln(app.out, "Shows technique details or detection notes for a technique.")
	fmt.Fprintln(app.out, "Global options: --matrix <matrix>, --plain")
}

func (app *App) printListHelp() {
	fmt.Fprintln(app.out, "Usage: go run . list <target>")
	fmt.Fprintln(app.out)
	fmt.Fprintln(app.out, "Targets:")
	fmt.Fprintln(app.out, "  techniques (aliases: tech, techs)")
	fmt.Fprintln(app.out, "  groups")
	fmt.Fprintln(app.out, "  mitigations")
	fmt.Fprintln(app.out, "  software")
	fmt.Fprintln(app.out, "  campaigns")
	fmt.Fprintln(app.out, "  detections (aliases: det, dets)")
	fmt.Fprintln(app.out, "  analytics")
	fmt.Fprintln(app.out, "  data-components (aliases: dc, dcs)")
	fmt.Fprintln(app.out, "  tactics")
	fmt.Fprintln(app.out, "  platforms")
	fmt.Fprintln(app.out)
	fmt.Fprintln(app.out, "Lists supported targets with pagination.")
	fmt.Fprintln(app.out)
	fmt.Fprintln(app.out, "Technique filters:")
	fmt.Fprintln(app.out, "  go run . list techniques --tactic <tactic_name>")
	fmt.Fprintln(app.out, "  go run . list techniques --platform <platform_name>")
	fmt.Fprintln(app.out, "  go run . list techniques --data-component <data_component_name>")
	fmt.Fprintln(app.out)
	fmt.Fprintln(app.out, "Only techniques accept filters. Global options: --matrix <matrix>, --plain")
}

func (app *App) printEntityHelp(entity, idName string, supportsTechniques, supportsAnalytics, supportsComponents bool) {
	fmt.Fprintf(app.out, "Usage: go run . %s <%s> [flags]\n", entity, idName)
	fmt.Fprintln(app.out)
	fmt.Fprintf(app.out, "Shows %s details", entity)

	if supportsTechniques || supportsAnalytics || supportsComponents {
		fmt.Fprint(app.out, " and optionally expands mapped relationships")
	}

	fmt.Fprintln(app.out, ".")
	fmt.Fprintln(app.out)
	fmt.Fprintln(app.out, "Flags:")

	if supportsTechniques {
		fmt.Fprintln(app.out, "  -t, --techniques  Show mapped techniques")
		fmt.Fprintln(app.out, "  -d, --detailed    Show detailed mapped techniques (requires -t)")
	}
	if supportsAnalytics {
		fmt.Fprintln(app.out, "  -a, --analytics   Show mapped analytics")
	}
	if supportsComponents {
		fmt.Fprintln(app.out, "  -c, --components  Show mapped data components")
	}

	fmt.Fprintln(app.out, "  --plain           Disable colored output")
	fmt.Fprintln(app.out, "  --matrix <matrix> Select ATT&CK matrix")
}

func (app *App) printStatusHelp() {
	fmt.Fprintln(app.out, "Usage: go run . status")
	fmt.Fprintln(app.out)
	fmt.Fprintln(app.out, "Shows cache status, update metadata, parsed entity counts, and tactic validation.")
	fmt.Fprintln(app.out, "A missing cache is reported as status information.")
	fmt.Fprintln(app.out, "Global options: --matrix <matrix>, --plain")
}

func (app *App) printExportHelp() {
	fmt.Fprintln(app.out, "Usage: go run . export <target> [--for <id_or_name>] [--format csv|md] --out <file>")
	fmt.Fprintln(app.out)
	fmt.Fprintln(app.out, "Exports cached data into CSV or Markdown reports with matrix-aware metadata.")
	fmt.Fprintln(app.out)
	fmt.Fprintln(app.out, "Targets:")
	fmt.Fprintln(app.out, "  summary")
	fmt.Fprintln(app.out, "  techniques")
	fmt.Fprintln(app.out, "  groups")
	fmt.Fprintln(app.out, "  mitigations")
	fmt.Fprintln(app.out, "  software")
	fmt.Fprintln(app.out, "  campaigns")
	fmt.Fprintln(app.out, "  detections")
	fmt.Fprintln(app.out, "  analytics")
	fmt.Fprintln(app.out, "  data-components")
	fmt.Fprintln(app.out)
	fmt.Fprintln(app.out, "Mapped relationship targets:")
	fmt.Fprintln(app.out, "  group-techniques")
	fmt.Fprintln(app.out, "  mitigation-techniques")
	fmt.Fprintln(app.out, "  software-techniques")
	fmt.Fprintln(app.out, "  campaign-techniques")
	fmt.Fprintln(app.out, "  detection-techniques")
	fmt.Fprintln(app.out, "  detection-analytics")
	fmt.Fprintln(app.out, "  detection-components")
	fmt.Fprintln(app.out, "  analytic-components")
	fmt.Fprintln(app.out)
	fmt.Fprintln(app.out, "Options:")
	fmt.Fprintln(app.out, "  --out <file>       Required output path")
	fmt.Fprintln(app.out, "  --format csv|md    Output format (default: csv)")
	fmt.Fprintln(app.out, "  --for <id_or_name> Required only for mapped relationship targets")
	fmt.Fprintln(app.out, "  --matrix <matrix>  Select ATT&CK matrix")
	fmt.Fprintln(app.out, "  --plain            Disable colored terminal messages")
	fmt.Fprintln(app.out)
	fmt.Fprintln(app.out, "Examples:")
	fmt.Fprintln(app.out, "  go run . export summary --matrix enterprise --format md --out reports/enterprise-summary.md")
	fmt.Fprintln(app.out, "  go run . export techniques --matrix mobile --format csv --out reports/mobile-techniques.csv")
	fmt.Fprintln(app.out, "  go run . export group-techniques --for <group_id_or_name> --matrix enterprise --format md --out reports/group-techniques.md")
}

func (app *App) printTUIHelp() {
	fmt.Fprintln(app.out, "Usage: go run . tui")
	fmt.Fprintln(app.out)
	fmt.Fprintln(app.out, "Opens the full-screen terminal interface for tactic and technique navigation.")
	fmt.Fprintln(app.out)
	fmt.Fprintln(app.out, "Keys:")
	fmt.Fprintln(app.out, "  Up/k, Down/j        Move through the current list")
	fmt.Fprintln(app.out, "  Enter               Open the selected item")
	fmt.Fprintln(app.out, "  b, Esc              Return to the previous screen")
	fmt.Fprintln(app.out, "  q, Ctrl+C           Exit the TUI")
	fmt.Fprintln(app.out)
	fmt.Fprintln(app.out, "Global options: --matrix <matrix>, --plain")
}
