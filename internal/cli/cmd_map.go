package cli

import (
	"fmt"
	"strings"

	"mitre-explorer/internal/attack"
)

type EntityFlags struct {
	Techniques bool
	Analytics  bool
	Components bool
	Detailed   bool
}

func parseEntityFlags(args []string) (EntityFlags, error) {
	var flags EntityFlags

	for _, arg := range args {
		switch arg {
		case "-t", "--techniques":
			flags.Techniques = true
		case "-a", "--analytics":
			flags.Analytics = true
		case "-c", "--components":
			flags.Components = true
		case "-d", "--detailed":
			flags.Detailed = true
		default:
			return EntityFlags{}, fmt.Errorf("unknown option: %s", arg)
		}
	}
	return flags, nil
}

func validateEntityFlags(entity string, flags EntityFlags) error {
	switch entity {
	case "group", "mitigation", "software", "campaign":
		if flags.Analytics {
			return fmt.Errorf("%s does not support -a/--analytics", entity)
		}
		if flags.Components {
			return fmt.Errorf("%s does not support -c/--components", entity)
		}
		if flags.Detailed && !flags.Techniques {
			return fmt.Errorf("-d/--detailed requires -t/--techniques")
		}

	case "detection":
		if flags.Detailed && !flags.Techniques {
			return fmt.Errorf("-d/--detailed requires -t/--techniques")
		}
	case "analytic":
		if flags.Techniques {
			return fmt.Errorf("%s does not support -t/--techniques", entity)
		}
		if flags.Detailed {
			return fmt.Errorf("%s does not support -d/--detailed", entity)
		}
		if flags.Analytics {
			return fmt.Errorf("%s does not support -a/--analytics", entity)
		}

	default:
		return fmt.Errorf("unknown entity type: %s", entity)
	}
	return nil
}

func (app *App) printTechniqueMapping(titleText string, results []attack.Technique, detailed bool) {
	if len(results) == 0 {
		app.printNoMappedResults("techniques", titleText)
		return
	}

	fmt.Fprintf(app.out, "%s %d technique(s)\n", app.ok("Found"), len(results))
	app.printMappedTechniquesWithMode(results, detailed)
}

func (app *App) printAnalyticMapping(results []attack.Analytic) {
	if len(results) == 0 {
		app.printNoMappedResults("analytics", "detection strategy")
		return
	}

	fmt.Fprintf(app.out, "%s %d analytic(s)\n", app.ok("Found"), len(results))
	app.printAnalyticList(results)
}

func (app *App) printComponentMapping(source string, results []attack.DataComponent) {
	if len(results) == 0 {
		app.printNoMappedResults("data components", source)
		return
	}

	fmt.Fprintf(app.out, "%s %d data component(s)\n", app.ok("Found"), len(results))
	app.printDataComponentList(results)
}

func (app *App) handleGroup(args []string) error {
	flags, err := entityOptions("group", args)
	if err != nil {
		return err
	}

	groupInput := args[1]
	cache, err := app.loadCacheForCommand()
	if err != nil {
		return err
	}

	g, found := attack.FindGroup(cache, groupInput)
	if !found {
		return fmt.Errorf("group %q not found in cache.", groupInput)
	}

	related := attack.TechniquesUsedByGroup(cache, g.ID)

	app.printSection("Group Details")
	app.printDetails([]DetailField{
		{"ID:", g.ID},
		{"Name:", g.Name},
		{"Aliases:", strings.Join(g.Aliases, ", ")},
		{"Mapped techniques:", fmt.Sprintf("%d", len(related))},
		{"Description:", g.Description},
	})

	if flags.Techniques {
		app.printSubsection("Mapped Techniques")
		app.printTechniqueMapping("group", related, flags.Detailed)
	}
	return nil
}

func (app *App) handleMitigation(args []string) error {
	flags, err := entityOptions("mitigation", args)
	if err != nil {
		return err
	}

	mitigationInput := args[1]
	cache, err := app.loadCacheForCommand()
	if err != nil {
		return err
	}

	m, found := attack.FindMitigation(cache, mitigationInput)
	if !found {
		return fmt.Errorf("mitigation %q not found in cache.", mitigationInput)
	}

	related := attack.TechniquesMitigatedBy(cache, m.ID)

	app.printSection("Mitigation Details")
	app.printDetails([]DetailField{
		{"ID:", m.ID},
		{"Name:", m.Name},
		{"Mapped techniques:", fmt.Sprintf("%d", len(related))},
		{"Description:", m.Description},
	})

	if flags.Techniques {
		app.printSubsection("Mapped Techniques")
		app.printTechniqueMapping("mitigation", related, flags.Detailed)
	}
	return nil
}

func (app *App) handleSoftware(args []string) error {
	flags, err := entityOptions("software", args)
	if err != nil {
		return err
	}

	softwareInput := args[1]
	cache, err := app.loadCacheForCommand()
	if err != nil {
		return err
	}

	s, found := attack.FindSoftware(cache, softwareInput)
	if !found {
		return fmt.Errorf("software %q not found in cache.", softwareInput)
	}

	related := attack.TechniquesUsedBySoftware(cache, s.ID)

	app.printSection("Software Details")
	app.printDetails([]DetailField{
		{"ID:", s.ID},
		{"Name:", s.Name},
		{"Type:", s.Type},
		{"Aliases:", strings.Join(s.Aliases, ", ")},
		{"Mapped techniques:", fmt.Sprintf("%d", len(related))},
		{"Description:", s.Description},
	})

	if flags.Techniques {
		app.printSubsection("Mapped Techniques")
		app.printTechniqueMapping("software", related, flags.Detailed)
	}
	return nil
}

func (app *App) handleCampaign(args []string) error {
	flags, err := entityOptions("campaign", args)
	if err != nil {
		return err
	}

	campaignInput := args[1]
	cache, err := app.loadCacheForCommand()
	if err != nil {
		return err
	}

	c, found := attack.FindCampaign(cache, campaignInput)
	if !found {
		return fmt.Errorf("campaign %q not found in cache.", campaignInput)
	}

	related := attack.TechniquesUsedByCampaign(cache, c.ID)

	app.printSection("Campaign Details")
	app.printDetails([]DetailField{
		{"ID:", c.ID},
		{"Name:", c.Name},
		{"Aliases:", strings.Join(c.Aliases, ", ")},
		{"Mapped techniques:", fmt.Sprintf("%d", len(related))},
		{"Description:", c.Description},
	})

	if flags.Techniques {
		app.printSubsection("Mapped Techniques")
		app.printTechniqueMapping("campaign", related, flags.Detailed)
	}
	return nil
}

func (app *App) handleDetection(args []string) error {
	flags, err := entityOptions("detection", args)
	if err != nil {
		return err
	}

	detectionInput := args[1]
	cache, err := app.loadCacheForCommand()
	if err != nil {
		return err
	}

	d, found := attack.FindDetectionStrategy(cache, detectionInput)
	if !found {
		return fmt.Errorf("detection strategy %q not found in cache.", detectionInput)
	}

	techniques := attack.TechniquesDetectedByStrategy(cache, d.ID)
	analytics := attack.AnalyticsByDetectionStrategy(cache, d.ID)
	components := attack.DataComponentsByDetectionStrategy(cache, d.ID)

	app.printSection("Detection Strategy Details")
	app.printDetails([]DetailField{
		{"ID:", d.ID},
		{"Name:", d.Name},
		{"Mapped techniques:", fmt.Sprintf("%d", len(techniques))},
		{"Analytics:", fmt.Sprintf("%d", len(analytics))},
		{"Data Components:", fmt.Sprintf("%d", len(components))},
		{"Description:", d.Description},
	})

	if flags.Techniques {
		app.printSubsection("Mapped Techniques")
		app.printTechniqueMapping("detection strategy", techniques, flags.Detailed)
	}

	if flags.Analytics {
		app.printSubsection("Analytics")
		app.printAnalyticMapping(analytics)
	}

	if flags.Components {
		app.printSubsection("Data Components")
		app.printComponentMapping("detection strategy", components)
	}
	return nil
}

func (app *App) handleAnalytic(args []string) error {
	flags, err := entityOptions("analytic", args)
	if err != nil {
		return err
	}

	analyticInput := args[1]
	cache, err := app.loadCacheForCommand()
	if err != nil {
		return err
	}

	a, found := attack.FindAnalytic(cache, analyticInput)
	if !found {
		return fmt.Errorf("analytic %q not found in cache.", analyticInput)
	}

	components := attack.DataComponentsByAnalytic(cache, a.ID)

	app.printSection("Analytic Details")
	app.printDetails([]DetailField{
		{"ID:", a.ID},
		{"Name:", a.Name},
		{"Data Components:", fmt.Sprintf("%d", len(components))},
		{"Description:", a.Description},
	})

	if flags.Components {
		app.printSubsection("Data Components")
		app.printComponentMapping("analytic", components)
	}
	return nil
}

func entityOptions(entity string, args []string) (EntityFlags, error) {
	if len(args) < 2 {
		return EntityFlags{}, invalidUsage("%s requires an ID or name", entity)
	}
	if err := requireOperand(args[1], entity+" ID or name"); err != nil {
		return EntityFlags{}, err
	}
	flags, err := parseEntityFlags(args[2:])
	if err != nil {
		return EntityFlags{}, invalidUsage("%s: %v", entity, err)
	}
	if err := validateEntityFlags(entity, flags); err != nil {
		return EntityFlags{}, invalidUsage("%s: %v", entity, err)
	}
	return flags, nil
}
