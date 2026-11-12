package cli

import (
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
	{"procedures", "Procedure Examples"},
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
		printMappedEntityTable(app, "Groups", "technique", attack.GroupsUsingTechnique(cache, techniqueID), app.printGroupTable)
	case "software":
		printMappedEntityTable(app, "Software", "technique", attack.SoftwareUsingTechnique(cache, techniqueID), app.printSoftwareTable)
	case "campaigns":
		printMappedEntityTable(app, "Campaigns", "technique", attack.CampaignsUsingTechnique(cache, techniqueID), app.printCampaignTable)
	case "mitigations":
		printMappedEntityTable(app, "Mitigations", "technique", attack.MitigationsForTechnique(cache, techniqueID), app.printMitigationTable)
	case "detections":
		printMappedEntityTable(app, "Detection Strategies", "technique", attack.DetectionStrategiesForTechnique(cache, techniqueID), app.printDetectionTable)
	case "procedures":
		app.printProcedures(attack.ProcedureExamplesForTechnique(cache, techniqueID))
	}
}
