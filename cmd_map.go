package main

import (
	"fmt"
	"os"
	"strings"
)

func handleGroup(args []string) {
	if len(args) < 3 {
		fmt.Println("Usage:")
		fmt.Println("  go run . group techniques <group_id_or_name> [--detailed] [--plain]")
		return
	}

	cache, err := loadCacheData(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println(errText("Cache not found. Run: go run . update"))
			return
		}
		fmt.Printf("Error loading cache: %v\n", err)
		return
	}

	sub := strings.ToLower(args[1])

	switch sub {
	case "show":
		if len(args) < 3 {
			fmt.Println("Usage: go run . group show <group_id_or_name> [--plain]")
			return
		}

		groupInput := args[2]
		g, found := findGroup(cache, groupInput)
		if !found {
			fmt.Printf("Group %q not found in cache.\n", groupInput)
			return
		}

		related := techniquesUsedByGroup(cache, g.ID)

		fmt.Printf("%s %s\n", label("ID:"), g.ID)
		fmt.Printf("%s %s\n", label("Name:"), g.Name)
		fmt.Printf("%s %s\n", label("Aliases:"), strings.Join(g.Aliases, ", "))
		fmt.Printf("%s %d\n", label("Mapped techniques:"), len(related))
		fmt.Printf("%s %s\n", label("Description:"), g.Description)

	case "techniques":
		detailed := false
		filtered := make([]string, 0, len(args))
		filtered = append(filtered, args[0], args[1])

		for _, a := range args[2:] {
			if a == "--detailed" {
				detailed = true
				continue
			}
			if strings.HasPrefix(a, "-") {
				fmt.Println("Usage: go run . group techniques <group_id_or_name> [--detailed] [--plain]")
				return
			}
			filtered = append(filtered, a)
		}
		args = filtered

		if len(args) != 3 {
			fmt.Println("Usage: go run . group techniques <group_id_or_name> [--detailed] [--plain]")
			return
		}

		groupInput := args[2]
		g, found := findGroup(cache, groupInput)
		if !found {
			fmt.Printf("Group %q not found in cache.\n", groupInput)
			return
		}

		results := techniquesUsedByGroup(cache, g.ID)
		if len(results) == 0 {
			fmt.Printf("No techniques mapped for group %s (%s).\n", g.Name, g.ID)
			return
		}

		fmt.Printf("%s %s (%s)\n", label("Group:"), g.Name, g.ID)
		fmt.Printf("%s %d technique(s)\n", ok("Found"), len(results))

		printMappedTechniquesWithMode(results, detailed)

	default:
		fmt.Printf("Unknown group subcommand: %s\n", sub)
		fmt.Println("Use: group techniques <group_id_or_name>")
	}
}

func handleMitigation(args []string) {
	if len(args) < 3 {
		fmt.Println("Usage:")
		fmt.Println("  go run . mitigation techniques <mitigation_id_or_name> [--detailed] [--plain]")
		return
	}

	cache, err := loadCacheData(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println(errText("Cache not found. Run: go run . update"))
			return
		}
		fmt.Printf("Error loading cache: %v\n", err)
		return
	}

	sub := strings.ToLower(args[1])

	switch sub {
	case "techniques":
		detailed := false
		filtered := make([]string, 0, len(args))
		filtered = append(filtered, args[0], args[1])

		for _, a := range args[2:] {
			if a == "--detailed" {
				detailed = true
				continue
			}
			if strings.HasPrefix(a, "-") {
				fmt.Println("Usage: go run . mitigation techniques <mitigation_id_or_name> [--detailed] [--plain]")
				return
			}
			filtered = append(filtered, a)
		}
		args = filtered

		if len(args) != 3 {
			fmt.Println("Usage: go run . mitigation techniques <mitigation_id_or_name> [--detailed] [--plain]")
			return
		}

		mitInput := args[2]
		m, found := findMitigation(cache, mitInput)

		if !found {
			fmt.Printf("Mitigation %q not found in cache.\n", mitInput)
			return
		}

		results := techniquesMitigatedBy(cache, m.ID)

		if len(results) == 0 {
			fmt.Printf("No techniques mapped for mitigation %s (%s).\n", m.Name, m.ID)
			return
		}

		fmt.Printf("%s %s (%s)\n", label("Mitigation:"), m.Name, m.ID)
		fmt.Printf("%s %d technique(s)\n", ok("Found"), len(results))

		printMappedTechniquesWithMode(results, detailed)

	default:
		fmt.Printf("Unknown mitigation subcommand: %s\n", sub)
		fmt.Println("Use: mitigation techniques <mitigation_id_or_name>")
	}
}

func handleSoftware(args []string) {
	if len(args) < 3 {
		fmt.Println("Usage:")
		fmt.Println("  go run . software show <software_id_or_name> [--plain]")
		fmt.Println("  go run . software techniques <software_id_or_name> [--detailed] [--plain]")
		return
	}

	cache, err := loadCacheData(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println(errText("Cache not found. Run: go run . update"))
			return
		}
		fmt.Printf("Error loading cache: %v\n", err)
		return
	}

	sub := strings.ToLower(args[1])

	switch sub {
	case "show":
		if len(args) != 3 {
			fmt.Println("Usage: go run . software show <software_id_or_name> [--plain]")
			return
		}

		softwareInput := args[2]
		s, found := findSoftware(cache, softwareInput)
		if !found {
			fmt.Printf("Software %q not found in cache.\n", softwareInput)
			return
		}

		related := techniquesUsedBySoftware(cache, s.ID)
		fmt.Printf("%s %s\n", label("ID:"), s.ID)
		fmt.Printf("%s %s\n", label("Name:"), s.Name)
		fmt.Printf("%s %s\n", label("Type:"), s.Type)
		fmt.Printf("%s %s\n", label("Aliases:"), strings.Join(s.Aliases, ", "))
		fmt.Printf("%s %d\n", label("Mapped techniques:"), len(related))
		fmt.Printf("%s %s\n", label("Description:"), s.Description)

	case "techniques":
		detailed := false
		filtered := make([]string, 0, len(args))
		filtered = append(filtered, args[0], args[1])

		for _, a := range args[2:] {
			if a == "--detailed" {
				detailed = true
				continue
			}
			if strings.HasPrefix(a, "-") {
				fmt.Println("Usage: go run . software techniques <software_id_or_name> [--detailed] [--plain]")
				return
			}
			filtered = append(filtered, a)
		}
		args = filtered

		if len(args) != 3 {
			fmt.Println("Usage: go run . software techniques <software_id_or_name> [--detailed] [--plain]")
			return
		}

		softwareInput := args[2]
		s, found := findSoftware(cache, softwareInput)
		if !found {
			fmt.Printf("Software %q not found in cache.\n", softwareInput)
			return
		}

		results := techniquesUsedBySoftware(cache, s.ID)
		if len(results) == 0 {
			fmt.Printf("No techniques mapped for software %s (%s).\n", s.Name, s.ID)
			return
		}

		fmt.Printf("%s %s (%s)\n", label("Software:"), s.Name, s.ID)
		fmt.Printf("%s %d technique(s)\n", ok("Found"), len(results))

		printMappedTechniquesWithMode(results, detailed)

	default:
		fmt.Printf("Unknown software subcommand: %s\n", sub)
		fmt.Println("Use: software show <software_id_or_name> or software techniques <software_id_or_name>")
	}
}

func handleCampaign(args []string) {
	if len(args) < 3 {
		fmt.Println("Usage:")
		fmt.Println("  go run . campaign show <campaign_id_or_name> [--plain]")
		fmt.Println("  go run . campaign techniques <campaign_id_or_name> [--detailed] [--plain]")
		return
	}

	cache, err := loadCacheData(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println(errText("Cache not found. Run: go run . update"))
			return
		}
		fmt.Printf("Error loading cache: %v\n", err)
		return
	}

	sub := strings.ToLower(args[1])

	switch sub {
	case "show":
		if len(args) != 3 {
			fmt.Println("Usage: go run . campaign show <campaign_id_or_name> [--plain]")
			return
		}
		campaignInput := args[2]
		c, found := findCampaign(cache, campaignInput)
		if !found {
			fmt.Printf("Campaign %q not found in cache.\n", campaignInput)
			return
		}

		related := techniquesUsedByCampaign(cache, c.ID)
		fmt.Printf("%s %s\n", label("ID:"), c.ID)
		fmt.Printf("%s %s\n", label("Name:"), c.Name)
		fmt.Printf("%s %s\n", label("Aliases:"), strings.Join(c.Aliases, ", "))
		fmt.Printf("%s %d\n", label("Mapped techniques:"), len(related))
		fmt.Printf("%s %s\n", label("Description:"), c.Description)

	case "techniques":
		detailed := false
		filtered := make([]string, 0, len(args))
		filtered = append(filtered, args[0], args[1])

		for _, a := range args[2:] {
			if a == "--detailed" {
				detailed = true
				continue
			}
			if strings.HasPrefix(a, "-") {
				fmt.Println("Usage: go run . campaign techniques <campaign_id_or_name> [--detailed] [--plain]")
				return
			}
			filtered = append(filtered, a)
		}
		args = filtered

		if len(args) != 3 {
			fmt.Println("Usage: go run . campaign techniques <campaign_id_or_name> [--detailed] [--plain]")
			return
		}
		campaignInput := args[2]
		c, found := findCampaign(cache, campaignInput)
		if !found {
			fmt.Printf("Campaign %q not found in cache.\n", campaignInput)
			return
		}

		results := techniquesUsedByCampaign(cache, c.ID)
		if len(results) == 0 {
			fmt.Printf("No techniques mapped for campaign %s (%s).\n", c.Name, c.ID)
			return
		}

		fmt.Printf("%s %s (%s)\n", label("Campaign:"), c.Name, c.ID)
		fmt.Printf("%s %d technique(s)\n", ok("Found"), len(results))
		printMappedTechniquesWithMode(results, detailed)

	default:
		fmt.Printf("Unknown campaign subcommand: %s\n", sub)
		fmt.Println("Use: campaign show <campaign_id_or_name> or campaign techniques <campaign_id_or_name>")
	}
}

func handleDetection(args []string) {
	if len(args) < 3 {
		fmt.Println("Usage:")
		fmt.Println("  go run . detection show <det_id_or_name> [--plain]")
		fmt.Println("  go run . detection techniques <det_id_or_name> [--detailed] [--plain]")
		fmt.Println("  go run . detection analytics <det_id_or_name> [--plain]")
		return
	}

	cache, err := loadCacheData(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println(errText("Cache not found. Run: go run . update"))
			return
		}
		fmt.Printf("Error loading cache: %v\n", err)
		return
	}

	sub := strings.ToLower(args[1])

	switch sub {
	case "show":
		d, found := findDetectionStrategy(cache, args[2])
		if !found {
			fmt.Printf("Detection strategy %q not found in cache.\n", args[2])
			return
		}

		related := techniquesDetectedByStrategy(cache, d.ID)
		fmt.Printf("%s %s\n", label("ID:"), d.ID)
		fmt.Printf("%s %s\n", label("Name:"), d.Name)
		fmt.Printf("%s %d\n", label("Mapped techniques:"), len(related))
		fmt.Printf("%s %d\n", label("Analytics:"), len(d.Analytics))
		fmt.Printf("%s %s\n", label("Description:"), d.Description)

	case "techniques":
		detailed := false
		filtered := make([]string, 0, len(args))
		filtered = append(filtered, args[0], args[1])

		for _, a := range args[2:] {
			if a == "--detailed" {
				detailed = true
				continue
			}
			if strings.HasPrefix(a, "-") {
				fmt.Println("Usage: go run . detection techniques <det_id_or_name> [--detailed] [--plain]")
				return
			}
			filtered = append(filtered, a)
		}
		args = filtered

		if len(args) != 3 {
			fmt.Println("Usage: go run . detection techniques <det_id_or_name> [--detailed] [--plain]")
			return
		}

		d, found := findDetectionStrategy(cache, args[2])
		if !found {
			fmt.Printf("Detection strategy %q not found in cache.\n", args[2])
			return
		}

		results := techniquesDetectedByStrategy(cache, d.ID)
		if len(results) == 0 {
			fmt.Printf("No techniques mapped for detection strategy %s (%s).\n", d.Name, d.ID)
			return
		}

		fmt.Printf("%s %s (%s)", label("Detection:"), d.Name, d.ID)
		fmt.Printf("%s %d technique(s)\n", ok("Found"), len(results))
		printMappedTechniquesWithMode(results, detailed)

	case "analytics":
		if len(args) != 3 {
			fmt.Println("Usage: go run . detection analysis <det_id_or_name> [--plain]")
			return
		}

		d, found := findDetectionStrategy(cache, args[2])
		if !found {
			fmt.Printf("Detection strategy %q not found in cache.\n", args[2])
			return
		}

		results := analyticsByDetectionStrategy(cache, d.ID)
		if len(results) == 0 {
			fmt.Printf("No analytics mapped for detection strategy %s (%s).\n", d.Name, d.ID)
			return
		}

		fmt.Printf("%s %s (%s)\n", label("Detection:"), d.Name, d.ID)
		fmt.Printf("%s %d analytic(s)\n", ok("Found"), len(results))

		for i, a := range results {
			fmt.Printf("%d. %s\n", i+1, a.ID)
		}

	default:
		fmt.Printf("Unknow detection subcommand: %s\n", sub)
		fmt.Println("Use: detection show <det_id_or_name>, detection techniques <det_id_or_name>, or detection analytics <det_id_or_name>")
	}
}
