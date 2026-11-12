package cli

import (
	"fmt"
	"strconv"
	"strings"

	"mitre-explorer/internal/attack"
)

type entityConnectionChoice struct {
	target string
	title  string
}

func entityConnectionChoices(entity string) []entityConnectionChoice {
	switch entity {
	case "group":
		return []entityConnectionChoice{{"software", "Software"}, {"campaigns", "Attributed Campaigns"}}
	case "software":
		return []entityConnectionChoice{{"groups", "Groups"}, {"campaigns", "Campaigns"}}
	case "campaign":
		return []entityConnectionChoice{{"software", "Software"}, {"groups", "Attributed Groups"}}
	default:
		return nil
	}
}

func (flags EntityFlags) connectionEnabled(target string) bool {
	switch target {
	case "groups":
		return flags.Groups
	case "software":
		return flags.Software
	case "campaigns":
		return flags.Campaigns
	default:
		return false
	}
}

func validateEntityConnections(entity string, flags EntityFlags) error {
	for _, target := range []string{"groups", "software", "campaigns"} {
		if !flags.connectionEnabled(target) {
			continue
		}
		allowed := false
		for _, choice := range entityConnectionChoices(entity) {
			if choice.target == target {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("%s does not support --%s", entity, target)
		}
	}
	return nil
}

func (app *App) printSelectedEntityConnections(cache attack.CacheData, entity, id string, flags EntityFlags) {
	for _, choice := range entityConnectionChoices(entity) {
		if flags.connectionEnabled(choice.target) {
			app.printEntityConnection(cache, entity, id, choice)
		}
	}
}

func (app *App) printEntityConnection(cache attack.CacheData, entity, id string, choice entityConnectionChoice) {
	switch {
	case entity == "group" && choice.target == "software":
		printMappedEntityTable(app, choice.title, entity, attack.SoftwareUsedByGroup(cache, id), app.printSoftwareTable)
	case entity == "group" && choice.target == "campaigns":
		printMappedEntityTable(app, choice.title, entity, attack.CampaignsAttributedToGroup(cache, id), app.printCampaignTable)
	case entity == "software" && choice.target == "groups":
		printMappedEntityTable(app, choice.title, entity, attack.GroupsUsingSoftware(cache, id), app.printGroupTable)
	case entity == "software" && choice.target == "campaigns":
		printMappedEntityTable(app, choice.title, entity, attack.CampaignsUsingSoftware(cache, id), app.printCampaignTable)
	case entity == "campaign" && choice.target == "software":
		printMappedEntityTable(app, choice.title, entity, attack.SoftwareUsedByCampaign(cache, id), app.printSoftwareTable)
	case entity == "campaign" && choice.target == "groups":
		printMappedEntityTable(app, choice.title, entity, attack.GroupsForCampaign(cache, id), app.printGroupTable)
	}
}

// Returning true requests the guided menu; false returns to the entity list.
func (app *App) runGuidedEntityMappings(cache attack.CacheData, entity, id string, techniques []attack.Technique) (bool, error) {
	choices := entityConnectionChoices(entity)
	viewed := make([]bool, len(choices)+1)
	for {
		fmt.Fprintln(app.out, "\nNext:")
		if !viewed[0] {
			fmt.Fprintln(app.out, "  [1] View mapped techniques")
		}
		for index, choice := range choices {
			if !viewed[index+1] {
				fmt.Fprintf(app.out, "  [%d] View %s\n", index+2, strings.ToLower(choice.title))
			}
		}
		fmt.Fprintln(app.out, "  [b] Back to the entity list")
		fmt.Fprintln(app.out, "  [q] Return to guided menu")
		fmt.Fprint(app.out, "> ")
		input, err := readLine(app.reader)
		if err != nil {
			return false, err
		}
		switch strings.ToLower(input) {
		case "b":
			return false, nil
		case "q":
			return true, nil
		}
		choice, err := strconv.Atoi(input)
		if err != nil || choice < 1 || choice > len(viewed) || viewed[choice-1] {
			app.printInvalidSelection()
			continue
		}
		if choice == 1 {
			app.printSubsection("Mapped Techniques")
			app.printTechniqueMapping(entity, techniques, false)
		} else {
			app.printEntityConnection(cache, entity, id, choices[choice-2])
		}
		viewed[choice-1] = true
	}
}
