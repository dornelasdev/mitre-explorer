package attack

import (
	"sort"
	"strings"
)

// GroupsUsingTechnique returns direct group mappings sorted by ID.
func GroupsUsingTechnique(cache CacheData, techniqueID string) []Group {
	return sourcesForTechnique(cache, techniqueID, "uses", "group", cache.Groups,
		func(group Group) (string, string) { return group.ID, "" })
}

// SoftwareUsingTechnique returns direct malware/tool mappings sorted by ID.
func SoftwareUsingTechnique(cache CacheData, techniqueID string) []Software {
	return sourcesForTechnique(cache, techniqueID, "uses", "software", cache.Softwares,
		func(software Software) (string, string) { return software.ID, "" })
}

// CampaignsUsingTechnique returns direct campaign mappings sorted by ID.
func CampaignsUsingTechnique(cache CacheData, techniqueID string) []Campaign {
	return sourcesForTechnique(cache, techniqueID, "uses", "campaign", cache.Campaigns,
		func(campaign Campaign) (string, string) { return campaign.ID, "" })
}

// MitigationsForTechnique returns mitigations linked directly to a technique,
// sorted by ID.
func MitigationsForTechnique(cache CacheData, techniqueID string) []Mitigation {
	return sourcesForTechnique(cache, techniqueID, "mitigates", "mitigation", cache.Mitigations,
		func(mitigation Mitigation) (string, string) { return mitigation.ID, "" })
}

// DetectionStrategiesForTechnique resolves external or STIX source references,
// sorted by external ID, falling back to the STIX ID when no external ID exists.
func DetectionStrategiesForTechnique(cache CacheData, techniqueID string) []DetectionStrategy {
	return sourcesForTechnique(cache, techniqueID, "detects", "detection_strategy", cache.DetectionStrategies,
		func(detection DetectionStrategy) (string, string) { return detection.ID, detection.StixID })
}

// Only direct edges to the exact technique are followed. Parent/sub-technique
// inheritance and transitive software usage would imply additional relationships.
func sourcesForTechnique[T any](cache CacheData, techniqueID, relationshipType, sourceType string, entities []T, ids func(T) (string, string)) []T {
	techniqueID = strings.TrimSpace(techniqueID)
	if techniqueID == "" {
		return nil
	}
	technique, found := FindTechniqueByID(cache.Techniques, techniqueID)
	if !found {
		return nil
	}

	sources := make(map[string]struct{})
	for _, rel := range cache.Relationships {
		if rel.Type != relationshipType || rel.SourceType != sourceType || rel.TargetType != "technique" || !strings.EqualFold(rel.TargetID, technique.ID) || rel.SourceID == "" {
			continue
		}
		sources[strings.ToLower(rel.SourceID)] = struct{}{}
	}
	if len(sources) == 0 {
		return nil
	}

	type match struct {
		entity T
		id     string
		key    string
	}
	var matches []match
	seen := make(map[string]struct{})
	for _, entity := range entities {
		id, stixID := ids(entity)
		_, externalMatch := sources[strings.ToLower(id)]
		_, stixMatch := sources[strings.ToLower(stixID)]
		if !externalMatch && !stixMatch {
			continue
		}
		key := strings.ToLower(referenceKey(id, stixID))
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		if id == "" {
			id = stixID
		}
		matches = append(matches, match{entity: entity, id: id, key: key})
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].id != matches[j].id {
			return matches[i].id < matches[j].id
		}
		return matches[i].key < matches[j].key
	})
	var out []T
	for _, match := range matches {
		out = append(out, match.entity)
	}
	return out
}
