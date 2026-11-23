package detailtext

import (
	"strings"

	"mitre-explorer/internal/attack"
)

const AssetCacheHint = "No assets in the ICS cache. To rebuild from the local dataset: go run . update --rebuild --matrix ics"

func AssetSections(asset attack.Asset) []Section {
	section := Section{Title: "Related Asset Examples"}
	for _, example := range asset.RelatedAssets {
		label := strings.TrimSpace(example.Name)
		if sectors := strings.Join(example.Sectors, ", "); strings.TrimSpace(sectors) != "" {
			if label == "" {
				label = "Sectors: " + sectors
			} else {
				label += " (sectors: " + sectors + ")"
			}
		}
		description := strings.TrimSpace(example.Description)
		switch {
		case label != "" && description != "":
			section.Entries = append(section.Entries, label+": "+description)
		case label != "":
			section.Entries = append(section.Entries, label)
		case description != "":
			section.Entries = append(section.Entries, description)
		}
	}
	if len(section.Entries) == 0 {
		return nil
	}
	return []Section{section}
}
