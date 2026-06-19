package main

import (
	"fmt"
	"os"
	"strings"
)

type EntityFlags struct {
	Techniques bool
	Analytics bool
	Components bool
	Detailed bool
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

func loadCacheForCommand() (CacheData, bool) {
	cache, err := loadCacheData(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println(errText("Cache not found. Run: go run . update"))
			return CacheData{}, false
		}
		fmt.Printf("Error loading cache: %v\n", err)
		return CacheData{}, false
	}

	return cache, true
}

func printTechniqueMapping(titleText string, results []Technique, detailed bool) {
	if len(results) == 0 {
		printNoMappedResults("techniques", titleText)
		return
	}

	fmt.Printf("%s %d technique(s)\n", ok("Found"), len(results))
	printMappedTechniquesWithMode(results, detailed)
}

func printAnalyticMapping(results []Analytic) {
	if len(results) == 0 {
		printNoMappedResults("analytics", "detection strategy")
		return
	}

	fmt.Printf("%s %d analytic(s)\n", ok("Found"), len(results))
	printAnalyticList(results)
}

func printComponentMapping(source string, results []DataComponent) {
	if len(results) == 0 {
		printNoMappedResults("data components", source)
		return
	}

	fmt.Printf("%s %d data component(s)\n", ok("Found"), len(results))
	printDataComponentList(results)
}

func handleGroup(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: go run . group <group_id>")
		return
	}

	cache, ok := loadCacheForCommand()
	if !ok {
		return
	}

	groupInput := args[1]
	flags, err := parseEntityFlags(args[2:])
	if err != nil {
		fmt.Println(errText(err.Error()))
		fmt.Println("Usage: go run . group <group_id> [-t|--techniques] [-d|--detailed] [--plain]")
		return
	}

	if err := validateEntityFlags("group", flags); err != nil {
		fmt.Println(errText(err.Error()))
		fmt.Println("Usage: go run . group <group_id> [-t|--techniques] [-d|--detailed] [--plain]")
		return
	}

	g, found := findGroup(cache, groupInput)
	if !found {
		fmt.Printf("Group %q not found in cache.\n", groupInput)
		return
	}

	related := techniquesUsedByGroup(cache, g.ID)

	printSection("Group Details")
	printDetails([]DetailField{
		{"ID:", g.ID},
		{"Name:", g.Name},
		{"Aliases:", strings.Join(g.Aliases, ", ")},
		{"Mapped techniques:", fmt.Sprintf("%d", len(related))},
		{"Description:", g.Description},
	})

	if flags.Techniques {
		printSubsection("Mapped Techniques")
		printTechniqueMapping("group", related, flags.Detailed)
	}
}

func handleMitigation(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: go run . mitigation <mitigation_id> [-t|--techniques] [-d|--detailed] [--plain]")
		return
	}

	cache, ok := loadCacheForCommand()
	if !ok {
		return
	}

	mitigationInput := args[1]
	flags, err := parseEntityFlags(args[2:])
	if err != nil {
		fmt.Println(errText(err.Error()))
		fmt.Println("Usage: go run . mitigation <mitigation_id> [-t|--techniques] [-d|--detailed] [--plain]")
		return
	}

	if err := validateEntityFlags("mitigation", flags); err != nil {
		fmt.Println(errText(err.Error()))
		fmt.Println("Usage: go run . mitigation <mitigation_id> [-t|--techniques] [-d|--detailed] [--plain]")
		return
	}

	m, found := findMitigation(cache, mitigationInput)
	if !found {
		fmt.Printf("Mitigation %q not found in cache.\n", mitigationInput)
		return
	}

	related := techniquesMitigatedBy(cache, m.ID)

	printSection("Mitigation Details")
	printDetails([]DetailField{
		{"ID:", m.ID},
		{"Name:", m.Name},
		{"Mapped techniques:", fmt.Sprintf("%d", len(related))},
		{"Description:", m.Description},
	})

	if flags.Techniques {
		printSubsection("Mapped Techniques")
		printTechniqueMapping("mitigation", related, flags.Detailed)
	}
}

func handleSoftware(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: go run . software <software_id> [-t|--techniques] [-d|--detailed] [--plain]")
		return
	}

	cache, ok := loadCacheForCommand()
	if !ok {
		return
	}

	softwareInput := args[1]
	flags, err := parseEntityFlags(args[2:])
	if err != nil {
		fmt.Println(errText(err.Error()))
		fmt.Println("Usage: go run . software <software_id> [-t|--techniques] [-d|--detailed] [--plain]")
		return
	}

	if err := validateEntityFlags("software", flags); err != nil {
		fmt.Println(errText(err.Error()))
		fmt.Println("Usage: go run . software <software_id> [-t|--techniques] [-d|--detailed] [--plain]")
		return
	}

	s, found := findSoftware(cache, softwareInput)
	if !found {
		fmt.Printf("Software %q not found in cache.\n", softwareInput)
		return
	}

	related := techniquesUsedBySoftware(cache, s.ID)

	printSection("Software Details")
	printDetails([]DetailField{
		{"ID:", s.ID},
		{"Name:", s.Name},
		{"Type:", s.Type},
		{"Aliases:", strings.Join(s.Aliases, ", ")},
		{"Mapped techniques:", fmt.Sprintf("%d", len(related))},
		{"Description:", s.Description},
	})

	if flags.Techniques {
		printSubsection("Mapped Techniques")
		printTechniqueMapping("software", related, flags.Detailed)
	}
}

func handleCampaign(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: go run . campaign <campaign_id> [-t|--techniques] [-d|--detailed] [--plain]")
		return
	}

	cache, ok := loadCacheForCommand()
	if !ok {
		return
	}

	campaignInput := args[1]
	flags, err := parseEntityFlags(args[2:])
	if err != nil {
		fmt.Println(errText(err.Error()))
		fmt.Println("Usage: go run . campaign <campaign_id> [-t|--techniques] [-d|--detailed] [--plain]")
		return
	}

	if err := validateEntityFlags("campaign", flags); err != nil {
		fmt.Println(errText(err.Error()))
		fmt.Println("Usage: go run . campaign <campaign_id> [-t|--techniques] [-d|--detailed] [--plain]")
		return
	}

	c, found := findCampaign(cache, campaignInput)
	if !found {
		fmt.Printf("Campaign %q not found in cache.\n", campaignInput)
		return
	}

	related := techniquesUsedByCampaign(cache, c.ID)

	printSection("Campaign Details")
	printDetails([]DetailField{
		{"ID:", c.ID},
		{"Name:", c.Name},
		{"Aliases:", strings.Join(c.Aliases, ", ")},
		{"Mapped techniques:", fmt.Sprintf("%d", len(related))},
		{"Description:", c.Description},
	})

	if flags.Techniques {
		printSubsection("Mapped Techniques")
		printTechniqueMapping("campaign", related, flags.Detailed)
	}
}

func handleDetection(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: go run . detection <detection_id> [-t|--techniques] [-a|--analytics] [-c|--components] [-d|--detailed] [--plain]")
		return
	}

	cache, ok := loadCacheForCommand()
	if !ok {
		return
	}

	detectionInput := args[1]
	flags, err := parseEntityFlags(args[2:])
	if err != nil {
		fmt.Println(errText(err.Error()))
		fmt.Println("Usage: go run . detection <detection_id> [-t|--techniques] [-a|--analytics] [-c|--components] [-d|--detailed] [--plain]")
		return
	}

	if err := validateEntityFlags("detection", flags); err != nil {
		fmt.Println(errText(err.Error()))
		fmt.Println("Usage: go run . detection <detection_id> [-t|--techniques] [-a|--analytics] [-c|--components] [-d|--detailed] [--plain]")
		return
	}

	d, found := findDetectionStrategy(cache, detectionInput)
	if !found {
		fmt.Printf("Detection strategy %q not found in cache.\n", detectionInput)
		return
	}

	techniques := techniquesDetectedByStrategy(cache, d.ID)
	analytics := analyticsByDetectionStrategy(cache, d.ID)
	components := dataComponentsByDetectionStrategy(cache, d.ID)

	printSection("Detection Strategy Details")
	printDetails([]DetailField{
		{"ID:", d.ID},
		{"Name:", d.Name},
		{"Mapped techniques:", fmt.Sprintf("%d", len(techniques))},
		{"Analytics:", fmt.Sprintf("%d", len(analytics))},
		{"Data Components:", fmt.Sprintf("%d", len(components))},
		{"Description:", d.Description},
	})

	if flags.Techniques {
		printSubsection("Mapped Techniques")
		printTechniqueMapping("detection strategy", techniques, flags.Detailed)
	}

	if flags.Analytics {
		printSubsection("Analytics")
		printAnalyticMapping(analytics)
	}

	if flags.Components {
		printSubsection("Data Components")
		printComponentMapping("detection strategy", components)
	}
}

func handleAnalytic(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: go run . analytic <analytic_id> [-c|--components] [--plain]")
		return
	}

	cache, ok := loadCacheForCommand()
	if !ok {
		return
	}

	analyticInput := args[1]
	flags, err := parseEntityFlags(args[2:])
	if err != nil {
		fmt.Println(errText(err.Error()))
		fmt.Println("Usage: go run . analytic <analytic_id> [-c|--components] [--plain]")
		return
	}

	if err := validateEntityFlags("analytic", flags); err != nil {
		fmt.Println(errText(err.Error()))
		fmt.Println("Usage: go run . analytic <analytic_id> [-c|--components] [--plain]")
		return
	}

	a, found := findAnalytic(cache, analyticInput)
	if !found {
		fmt.Printf("Analytic %q not found in cache.\n", analyticInput)
		return
	}

	components := dataComponentsByAnalytic(cache, a.ID)

	printSection("Analytic Details")
	printDetails([]DetailField{
		{"ID:", a.ID},
		{"Name:", a.Name},
		{"Data Components:", fmt.Sprintf("%d", len(components))},
		{"Description:", a.Description},
	})

	if flags.Components {
		printSubsection("Data Components")
		printComponentMapping("analytic", components)
	}
}
