package cli

import (
	"errors"
	"fmt"
	"strings"

	"mitre-explorer/internal/attack"
	"mitre-explorer/internal/detailtext"
)

func exportCoverageRows(cache attack.CacheData, target, input string) ([]string, [][]string, error) {
	switch target {
	case "assets", "asset-techniques", "technique-assets":
		return exportAssetRows(cache, target, input)
	case "technique-procedures":
		technique, found := attack.FindTechniqueByID(cache.Techniques, strings.TrimSpace(input))
		if !found {
			return nil, nil, fmt.Errorf("technique %q not found in cache", input)
		}
		headers, rows := exportProcedureRows(cache, technique)
		return headers, rows, nil
	default:
		return exportConnectionRows(cache, target, input)
	}
}

func exportAssetRows(cache attack.CacheData, target, input string) ([]string, [][]string, error) {
	if len(cache.Assets) == 0 {
		return nil, nil, errors.New(detailtext.AssetCacheHint)
	}
	switch target {
	case "assets":
		headers := []string{"ID", "Name", "STIX ID", "Platforms", "Sectors", "Description", "Related Asset Examples"}
		rows := make([][]string, 0, len(cache.Assets))
		for _, asset := range sortedAssets(cache.Assets) {
			var entries []string
			for _, section := range detailtext.AssetSections(asset) {
				entries = append(entries, section.Entries...)
			}
			rows = append(rows, []string{
				asset.ID, asset.Name, asset.StixID, strings.Join(asset.Platforms, ", "),
				strings.Join(asset.Sectors, ", "), asset.Description, strings.Join(entries, "\n"),
			})
		}
		return headers, rows, nil
	case "asset-techniques":
		asset, found := attack.FindAsset(cache, input)
		if !found {
			return nil, nil, fmt.Errorf("asset %q not found in the ICS cache", input)
		}
		headers, rows := mappedTechniquesRows(asset.ID, asset.Name, attack.TechniquesTargetingAsset(cache, asset.ID))
		return headers, rows, nil
	case "technique-assets":
		technique, found := attack.FindTechniqueByID(cache.Techniques, strings.TrimSpace(input))
		if !found {
			return nil, nil, fmt.Errorf("technique %q not found in cache", input)
		}
		headers := []string{"Source ID", "Source Name", "Asset ID", "Asset Name", "Platforms", "Sectors"}
		assets := attack.AssetsTargetedByTechnique(cache, technique.ID)
		rows := make([][]string, 0, len(assets))
		for _, asset := range assets {
			rows = append(rows, []string{
				technique.ID, technique.Name, asset.ID, asset.Name,
				strings.Join(asset.Platforms, ", "), strings.Join(asset.Sectors, ", "),
			})
		}
		return headers, rows, nil
	default:
		return nil, nil, invalidUsage("unknown asset export target: %s", target)
	}
}

func exportProcedureRows(cache attack.CacheData, technique attack.Technique) ([]string, [][]string) {
	headers := []string{
		"Technique ID", "Technique Name", "Source Type", "Source ID", "Source Name", "Relationship STIX ID",
		"Procedure", "Citation Source", "Citation Description", "Citation URL", "Citation External ID",
	}
	examples := attack.ProcedureExamplesForTechnique(cache, technique.ID)
	rows := make([][]string, 0, len(examples))
	for _, example := range examples {
		addRow := func(reference attack.ExternalReference) {
			rows = append(rows, []string{
				technique.ID, technique.Name, example.SourceType, example.SourceID, example.SourceName, example.StixID,
				example.Description, reference.SourceName, reference.Description, reference.URL, reference.ExternalID,
			})
		}
		if len(example.References) == 0 {
			addRow(attack.ExternalReference{})
		}
		for _, reference := range example.References {
			addRow(reference)
		}
	}
	return headers, rows
}

func exportConnectionRows(cache attack.CacheData, target, input string) ([]string, [][]string, error) {
	switch target {
	case "group-software", "group-campaigns":
		group, found := attack.FindGroup(cache, input)
		if !found {
			return nil, nil, fmt.Errorf("group %q not found in cache", input)
		}
		if target == "group-software" {
			return mappedEntityRows(group.ID, group.Name, "Software", attack.SoftwareUsedByGroup(cache, group.ID), softwareIDName)
		}
		return mappedEntityRows(group.ID, group.Name, "Campaign", attack.CampaignsAttributedToGroup(cache, group.ID), campaignIDName)
	case "software-groups", "software-campaigns":
		software, found := attack.FindSoftware(cache, input)
		if !found {
			return nil, nil, fmt.Errorf("software %q not found in cache", input)
		}
		if target == "software-groups" {
			return mappedEntityRows(software.ID, software.Name, "Group", attack.GroupsUsingSoftware(cache, software.ID), groupIDName)
		}
		return mappedEntityRows(software.ID, software.Name, "Campaign", attack.CampaignsUsingSoftware(cache, software.ID), campaignIDName)
	case "campaign-software", "campaign-groups":
		campaign, found := attack.FindCampaign(cache, input)
		if !found {
			return nil, nil, fmt.Errorf("campaign %q not found in cache", input)
		}
		if target == "campaign-software" {
			return mappedEntityRows(campaign.ID, campaign.Name, "Software", attack.SoftwareUsedByCampaign(cache, campaign.ID), softwareIDName)
		}
		return mappedEntityRows(campaign.ID, campaign.Name, "Group", attack.GroupsForCampaign(cache, campaign.ID), groupIDName)
	default:
		return nil, nil, invalidUsage("unknown export target: %s", target)
	}
}

func mappedEntityRows[T any](sourceID, sourceName, kind string, entities []T, idName func(T) (string, string)) ([]string, [][]string, error) {
	headers := []string{"Source ID", "Source Name", kind + " ID", kind + " Name"}
	rows := make([][]string, 0, len(entities))
	for _, entity := range entities {
		id, name := idName(entity)
		rows = append(rows, []string{sourceID, sourceName, id, name})
	}
	return headers, rows, nil
}

func groupIDName(group attack.Group) (string, string) { return group.ID, group.Name }
func softwareIDName(software attack.Software) (string, string) {
	return software.ID, software.Name
}
func campaignIDName(campaign attack.Campaign) (string, string) { return campaign.ID, campaign.Name }
