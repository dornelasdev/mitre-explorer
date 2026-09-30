package tui

import (
	"sort"
	"strings"

	"mitre-explorer/internal/attack"
)

type itemKind uint8

const (
	itemCategory itemKind = iota
	itemTactic
	itemTechnique
	itemGroup
	itemMitigation
	itemSoftware
	itemCampaign
	itemDetection
	itemAnalytic
	itemDataComponent
	itemRelation
)

type detailField struct {
	label string
	value string
}

type browseItem struct {
	kind        itemKind
	id          string
	name        string
	description string
	fields      []detailField
	count       int
	related     []browseItem
}

func (m model) explorePage() page {
	return page{
		kind:  pageList,
		title: "EXPLORE",
		items: []browseItem{
			{kind: itemCategory, id: "tactics", name: "Tactics", count: len(m.tactics)},
			{kind: itemCategory, id: "groups", name: "Groups", count: len(m.cache.Groups)},
			{kind: itemCategory, id: "mitigations", name: "Mitigations", count: len(m.cache.Mitigations)},
			{kind: itemCategory, id: "software", name: "Software", count: len(m.cache.Softwares)},
			{kind: itemCategory, id: "campaigns", name: "Campaigns", count: len(m.cache.Campaigns)},
			{kind: itemCategory, id: "detections", name: "Detection Strategies", count: len(m.cache.DetectionStrategies)},
			{kind: itemCategory, id: "analytics", name: "Analytics", count: len(m.cache.Analytics)},
			{kind: itemCategory, id: "data-components", name: "Data Components", count: len(m.cache.DataComponents)},
		},
	}
}

func (m model) itemsForCategory(category string) []browseItem {
	var items []browseItem
	switch category {
	case "tactics":
		for _, tactic := range m.tactics {
			items = append(items, browseItem{
				kind: itemTactic, id: tactic, name: tactic,
				count: len(attack.ListByTactic(m.cache.Techniques, tactic)),
			})
		}
	case "groups":
		for _, entity := range m.cache.Groups {
			items = append(items, groupItem(entity))
		}
	case "mitigations":
		for _, entity := range m.cache.Mitigations {
			items = append(items, mitigationItem(entity))
		}
	case "software":
		for _, entity := range m.cache.Softwares {
			items = append(items, softwareItem(entity))
		}
	case "campaigns":
		for _, entity := range m.cache.Campaigns {
			items = append(items, campaignItem(entity))
		}
	case "detections":
		for _, entity := range m.cache.DetectionStrategies {
			items = append(items, detectionItem(entity))
		}
	case "analytics":
		for _, entity := range m.cache.Analytics {
			items = append(items, analyticItem(entity))
		}
	case "data-components":
		for _, entity := range m.cache.DataComponents {
			items = append(items, dataComponentItem(entity))
		}
	}

	if category != "tactics" {
		sort.Slice(items, func(i, j int) bool {
			if items[i].name != items[j].name {
				return items[i].name < items[j].name
			}
			return items[i].id < items[j].id
		})
	}
	return items
}

func groupItem(entity attack.Group) browseItem {
	return browseItem{
		kind: itemGroup, id: entity.ID, name: entity.Name, description: entity.Description,
		fields: []detailField{{"Aliases", joinedOrUnavailable(entity.Aliases)}},
	}
}

func mitigationItem(entity attack.Mitigation) browseItem {
	return browseItem{kind: itemMitigation, id: entity.ID, name: entity.Name, description: entity.Description}
}

func softwareItem(entity attack.Software) browseItem {
	return browseItem{
		kind: itemSoftware, id: entity.ID, name: entity.Name, description: entity.Description,
		fields: []detailField{{"Type", entity.Type}, {"Aliases", joinedOrUnavailable(entity.Aliases)}},
	}
}

func campaignItem(entity attack.Campaign) browseItem {
	return browseItem{
		kind: itemCampaign, id: entity.ID, name: entity.Name, description: entity.Description,
		fields: []detailField{{"Aliases", joinedOrUnavailable(entity.Aliases)}},
	}
}

func detectionItem(entity attack.DetectionStrategy) browseItem {
	return browseItem{
		kind: itemDetection, id: firstNonEmpty(entity.ID, entity.StixID), name: entity.Name, description: entity.Description,
		fields: []detailField{{"STIX ID", entity.StixID}},
	}
}

func analyticItem(entity attack.Analytic) browseItem {
	return browseItem{
		kind: itemAnalytic, id: firstNonEmpty(entity.ID, entity.StixID), name: entity.Name, description: entity.Description,
		fields: []detailField{{"STIX ID", entity.StixID}},
	}
}

func dataComponentItem(entity attack.DataComponent) browseItem {
	return browseItem{
		kind: itemDataComponent, id: firstNonEmpty(entity.ID, entity.StixID), name: entity.Name, description: entity.Description,
		fields: []detailField{{"STIX ID", entity.StixID}},
	}
}

func techniqueItems(techniques []attack.Technique) []browseItem {
	items := make([]browseItem, 0, len(techniques))
	for _, technique := range techniques {
		items = append(items, browseItem{
			kind: itemTechnique, id: technique.ID, name: technique.Name, description: technique.Description,
			fields: []detailField{
				{"Tactics", joinedOrUnavailable(technique.Tactics)},
				{"Platforms", joinedOrUnavailable(technique.Platforms)},
				{"Data Sources", joinedOrUnavailable(technique.DataSources)},
				{"Detection Notes", strings.TrimSpace(technique.DetectionNotes)},
			},
		})
	}
	return items
}

func analyticItems(analytics []attack.Analytic) []browseItem {
	items := make([]browseItem, 0, len(analytics))
	for _, entity := range analytics {
		items = append(items, analyticItem(entity))
	}
	return items
}

func dataComponentItems(components []attack.DataComponent) []browseItem {
	items := make([]browseItem, 0, len(components))
	for _, entity := range components {
		items = append(items, dataComponentItem(entity))
	}
	return items
}

func (m model) relationItems(source browseItem) []browseItem {
	relation := func(name string, related []browseItem) browseItem {
		return browseItem{kind: itemRelation, name: name, count: len(related), related: related}
	}

	switch source.kind {
	case itemGroup:
		return []browseItem{relation("Mapped Techniques", techniqueItems(attack.TechniquesUsedByGroup(m.cache, source.id)))}
	case itemMitigation:
		return []browseItem{relation("Mitigated Techniques", techniqueItems(attack.TechniquesMitigatedBy(m.cache, source.id)))}
	case itemSoftware:
		return []browseItem{relation("Mapped Techniques", techniqueItems(attack.TechniquesUsedBySoftware(m.cache, source.id)))}
	case itemCampaign:
		return []browseItem{relation("Mapped Techniques", techniqueItems(attack.TechniquesUsedByCampaign(m.cache, source.id)))}
	case itemDetection:
		return []browseItem{
			relation("Detected Techniques", techniqueItems(attack.TechniquesDetectedByStrategy(m.cache, source.id))),
			relation("Analytics", analyticItems(attack.AnalyticsByDetectionStrategy(m.cache, source.id))),
			relation("Data Components", dataComponentItems(attack.DataComponentsByDetectionStrategy(m.cache, source.id))),
		}
	case itemAnalytic:
		return []browseItem{relation("Data Components", dataComponentItems(attack.DataComponentsByAnalytic(m.cache, source.id)))}
	case itemDataComponent:
		return []browseItem{relation("Mapped Techniques", techniqueItems(attack.TechniquesByDataComponent(m.cache, source.id)))}
	default:
		return nil
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return "Not available"
}
