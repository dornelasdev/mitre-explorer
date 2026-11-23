package cli

import (
	"fmt"
	"slices"
	"strings"

	"mitre-explorer/internal/attack"
	"mitre-explorer/internal/detailtext"
)

type techniqueMappingKind struct {
	target string
	title  string
}

var techniqueMappingKinds = []techniqueMappingKind{
	{"groups", "Groups"},
	{"software", "Software"},
	{"campaigns", "Campaigns"},
	{"mitigations", "Mitigations"},
	{"detections", "Detection Strategies"},
	{"procedures", "Procedure Examples"},
}

var icsTechniqueMappings = append(slices.Clone(techniqueMappingKinds), techniqueMappingKind{"assets", "Targeted Assets"})

func (app *App) techniqueMappings() []techniqueMappingKind {
	if app.activeMatrixName() == "ics" {
		return icsTechniqueMappings
	}
	return techniqueMappingKinds
}

type showOptions struct {
	techniqueID   string
	detectionOnly bool
	mappings      map[string]bool
}

func (app *App) parseShowOptions(args []string) (showOptions, error) {
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
	kinds := app.techniqueMappings()
	for _, flag := range args[2:] {
		if flag == "--assets" {
			if err := app.requireICSAssets(); err != nil {
				return showOptions{}, err
			}
		}
		matched := false
		for _, kind := range kinds {
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
	case "assets":
		app.printAssetMapping(cache, techniqueID)
	}
}

func (app *App) printAssetMapping(cache attack.CacheData, techniqueID string) {
	app.printSubsection("Targeted Assets")
	if len(cache.Assets) == 0 {
		fmt.Fprintln(app.out, detailtext.AssetCacheHint)
		return
	}
	assets := attack.AssetsTargetedByTechnique(cache, techniqueID)
	if len(assets) == 0 {
		app.printNoMappedResults("assets", "technique")
		return
	}
	fmt.Fprintf(app.out, "%s %d asset(s)\n", app.ok("Found"), len(assets))
	app.printAssetTable(assets)
}
