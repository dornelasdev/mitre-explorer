package cli

import (
	"fmt"
	"strings"

	"mitre-explorer/internal/attack"
)

var techniqueMappingKinds = []struct {
	target string
	title  string
}{
	{"groups", "Groups"},
	{"software", "Software"},
	{"campaigns", "Campaigns"},
	{"mitigations", "Mitigations"},
	{"detections", "Detection Strategies"},
}

type showOptions struct {
	techniqueID   string
	detectionOnly bool
	mappings      map[string]bool
}

func parseShowOptions(args []string) (showOptions, error) {
	var options showOptions
	if len(args) < 2 {
		return options, invalidUsage("show requires <technique_id> or detection <technique_id>")
	}
	if strings.EqualFold(args[1], "detection") {
		if len(args) != 3 {
			return options, invalidUsage("show detection requires exactly one technique ID")
		}
		options.detectionOnly = true
		options.techniqueID = args[2]
	} else {
		options.techniqueID = args[1]
	}
	if err := requireOperand(options.techniqueID, "technique ID"); err != nil {
		return options, err
	}
	options.techniqueID = strings.TrimSpace(options.techniqueID)
	if options.detectionOnly {
		return options, nil
	}

	options.mappings = make(map[string]bool)
	for _, flag := range args[2:] {
		matched := false
		for _, kind := range techniqueMappingKinds {
			if flag == "--all" || flag == "--"+kind.target {
				options.mappings[kind.target] = true
				matched = true
			}
		}
		if !matched {
			return showOptions{}, invalidUsage("unknown show option: %s", flag)
		}
	}
	return options, nil
}

func (app *App) printTechniqueEntities(cache attack.CacheData, techniqueID, target string) {
	switch target {
	case "groups":
		printTechniqueEntityTable(app, "Groups", attack.GroupsUsingTechnique(cache, techniqueID), app.printGroupTable)
	case "software":
		printTechniqueEntityTable(app, "Software", attack.SoftwareUsingTechnique(cache, techniqueID), app.printSoftwareTable)
	case "campaigns":
		printTechniqueEntityTable(app, "Campaigns", attack.CampaignsUsingTechnique(cache, techniqueID), app.printCampaignTable)
	case "mitigations":
		printTechniqueEntityTable(app, "Mitigations", attack.MitigationsForTechnique(cache, techniqueID), app.printMitigationTable)
	case "detections":
		printTechniqueEntityTable(app, "Detection Strategies", attack.DetectionStrategiesForTechnique(cache, techniqueID), app.printDetectionTable)
	}
}

func printTechniqueEntityTable[T any](app *App, title string, entities []T, printTable func([]T)) {
	app.printSubsection(title)
	if len(entities) == 0 {
		app.printNoMappedResults(strings.ToLower(title), "technique")
		return
	}
	fmt.Fprintf(app.out, "%s %d mapped item(s)\n", app.ok("Found"), len(entities))
	printTable(entities)
}
