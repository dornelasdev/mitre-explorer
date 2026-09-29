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
			items = append(items, browseItem{
				kind: itemGroup, id: entity.ID, name: entity.Name, description: entity.Description,
				fields: []detailField{{"Aliases", joinedOrUnavailable(entity.Aliases)}},
			})
		}
	case "mitigations":
		for _, entity := range m.cache.Mitigations {
			items = append(items, browseItem{kind: itemMitigation, id: entity.ID, name: entity.Name, description: entity.Description})
		}
	case "software":
		for _, entity := range m.cache.Softwares {
			items = append(items, browseItem{
				kind: itemSoftware, id: entity.ID, name: entity.Name, description: entity.Description,
				fields: []detailField{{"Type", entity.Type}, {"Aliases", joinedOrUnavailable(entity.Aliases)}},
			})
		}
	case "campaigns":
		for _, entity := range m.cache.Campaigns {
			items = append(items, browseItem{
				kind: itemCampaign, id: entity.ID, name: entity.Name, description: entity.Description,
				fields: []detailField{{"Aliases", joinedOrUnavailable(entity.Aliases)}},
			})
		}
	case "detections":
		for _, entity := range m.cache.DetectionStrategies {
			items = append(items, browseItem{
				kind: itemDetection, id: firstNonEmpty(entity.ID, entity.StixID), name: entity.Name, description: entity.Description,
				fields: []detailField{{"STIX ID", entity.StixID}},
			})
		}
	case "analytics":
		for _, entity := range m.cache.Analytics {
			items = append(items, browseItem{
				kind: itemAnalytic, id: firstNonEmpty(entity.ID, entity.StixID), name: entity.Name, description: entity.Description,
				fields: []detailField{{"STIX ID", entity.StixID}},
			})
		}
	case "data-components":
		for _, entity := range m.cache.DataComponents {
			items = append(items, browseItem{
				kind: itemDataComponent, id: firstNonEmpty(entity.ID, entity.StixID), name: entity.Name, description: entity.Description,
				fields: []detailField{{"STIX ID", entity.StixID}},
			})
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
		items = append(items, browseItem{
			kind: itemAnalytic, id: firstNonEmpty(entity.ID, entity.StixID), name: entity.Name, description: entity.Description,
			fields: []detailField{{"STIX ID", entity.StixID}},
		})
	}
	return items
}

func dataComponentItems(components []attack.DataComponent) []browseItem {
	items := make([]browseItem, 0, len(components))
	for _, entity := range components {
		items = append(items, browseItem{
			kind: itemDataComponent, id: firstNonEmpty(entity.ID, entity.StixID), name: entity.Name, description: entity.Description,
			fields: []detailField{{"STIX ID", entity.StixID}},
		})
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
