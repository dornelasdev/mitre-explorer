package attack

import (
	"sort"
	"strings"
)

// TechniquesUsedByGroup returns unique mapped techniques sorted by ID.
func TechniquesUsedByGroup(cache CacheData, groupID string) []Technique {
	return techniquesRelatedTo(cache, "uses", "group", groupID)
}

// TechniquesMitigatedBy returns unique mapped techniques sorted by ID.
func TechniquesMitigatedBy(cache CacheData, mitigationID string) []Technique {
	return techniquesRelatedTo(cache, "mitigates", "mitigation", mitigationID)
}

// TechniquesUsedBySoftware returns unique mapped techniques sorted by ID.
func TechniquesUsedBySoftware(cache CacheData, softwareID string) []Technique {
	return techniquesRelatedTo(cache, "uses", "software", softwareID)
}

// TechniquesUsedByCampaign returns unique mapped techniques sorted by ID.
func TechniquesUsedByCampaign(cache CacheData, campaignID string) []Technique {
	return techniquesRelatedTo(cache, "uses", "campaign", campaignID)
}

// TechniquesByDataComponent resolves component names/IDs through relationships.
// If none resolve to techniques, it falls back to legacy component/source text.
func TechniquesByDataComponent(cache CacheData, componentInput string) []Technique {
	componentInput = strings.TrimSpace(componentInput)
	q := strings.ToLower(componentInput)
	if q == "" {
		return nil
	}

	componentIDs := make(map[string]struct{})
	for _, dc := range cache.DataComponents {
		if strings.Contains(strings.ToLower(dc.Name), q) || strings.EqualFold(dc.ID, componentInput) || strings.EqualFold(dc.StixID, componentInput) {
			if dc.ID != "" {
				componentIDs[dc.ID] = struct{}{}
			}
			if dc.StixID != "" {
				componentIDs[dc.StixID] = struct{}{}
			}
		}
	}

	techByID := indexTechniques(cache.Techniques)

	seen := make(map[string]struct{})
	var out []Technique

	for _, rel := range cache.Relationships {
		if rel.Type != "has_data_component" || rel.SourceType != "technique" || rel.TargetType != "data_component" {
			continue
		}
		if _, ok := componentIDs[rel.TargetID]; !ok {
			continue
		}
		if _, ok := seen[rel.SourceID]; ok {
			continue
		}
		seen[rel.SourceID] = struct{}{}

		if t, ok := techByID[rel.SourceID]; ok {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		for _, t := range cache.Techniques {
			matched := false

			for _, dc := range t.DataComponents {
				if strings.Contains(strings.ToLower(dc), q) {
					matched = true
					break
				}
			}
			if !matched {
				for _, ds := range t.DataSources {
					if strings.Contains(strings.ToLower(ds), q) {
						matched = true
						break
					}
				}
			}

			if matched {
				out = append(out, t)
			}
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// TechniquesDetectedByStrategy returns unique mapped techniques sorted by ID.
func TechniquesDetectedByStrategy(cache CacheData, detectionID string) []Technique {
	return techniquesRelatedTo(cache, "detects", "detection_strategy", detectionID)
}

// AnalyticsByDetectionStrategy resolves external or STIX references and sorts by ID.
func AnalyticsByDetectionStrategy(cache CacheData, detectionID string) []Analytic {
	d, found := FindDetectionStrategy(cache, detectionID)
	if !found {
		return nil
	}

	analyticByID := make(map[string]Analytic, len(cache.Analytics))
	for _, a := range cache.Analytics {
		if a.ID != "" {
			analyticByID[a.ID] = a
		}
		if a.StixID != "" {
			analyticByID[a.StixID] = a
		}
	}

	seen := make(map[string]struct{})
	var out []Analytic

	for _, ref := range d.Analytics {
		a, ok := analyticByID[ref]
		if !ok {
			continue
		}
		key := referenceKey(a.ID, a.StixID)
		if _, exists := seen[key]; exists {
			continue
		}

		seen[key] = struct{}{}
		out = append(out, a)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// DataComponentsByAnalytic resolves component references and sorts by name, then ID.
func DataComponentsByAnalytic(cache CacheData, analyticID string) []DataComponent {
	a, found := FindAnalytic(cache, analyticID)
	if !found {
		return nil
	}

	componentByID := indexComponents(cache.DataComponents)
	seen := make(map[string]struct{})
	out := appendResolvedComponents(nil, a.DataComponents, componentByID, seen)
	sortComponents(out)
	return out
}

// DataComponentsByDetectionStrategy returns the union of linked analytics' components.
func DataComponentsByDetectionStrategy(cache CacheData, detectionID string) []DataComponent {
	analytics := AnalyticsByDetectionStrategy(cache, detectionID)
	if len(analytics) == 0 {
		return nil
	}
	componentByID := indexComponents(cache.DataComponents)

	seen := make(map[string]struct{})
	var out []DataComponent

	for _, a := range analytics {
		out = appendResolvedComponents(out, a.DataComponents, componentByID, seen)
	}

	sortComponents(out)
	return out
}

func techniquesRelatedTo(cache CacheData, relationshipType, sourceType, sourceID string) []Technique {
	techByID := indexTechniques(cache.Techniques)
	seen := make(map[string]struct{})
	var out []Technique
	for _, rel := range cache.Relationships {
		if rel.Type != relationshipType || rel.SourceType != sourceType || rel.TargetType != "technique" || !strings.EqualFold(rel.SourceID, sourceID) {
			continue
		}
		if _, exists := seen[rel.TargetID]; exists {
			continue
		}
		seen[rel.TargetID] = struct{}{}
		if technique, exists := techByID[rel.TargetID]; exists {
			out = append(out, technique)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func indexTechniques(techniques []Technique) map[string]Technique {
	index := make(map[string]Technique, len(techniques))
	for _, technique := range techniques {
		index[technique.ID] = technique
	}
	return index
}

func indexComponents(components []DataComponent) map[string]DataComponent {
	index := make(map[string]DataComponent, len(components)*2)
	for _, component := range components {
		if component.ID != "" {
			index[component.ID] = component
		}
		if component.StixID != "" {
			index[component.StixID] = component
		}
	}
	return index
}

func appendResolvedComponents(out []DataComponent, refs []string, index map[string]DataComponent, seen map[string]struct{}) []DataComponent {
	for _, ref := range refs {
		component, exists := index[ref]
		if !exists {
			continue
		}
		key := referenceKey(component.ID, component.StixID)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, component)
	}
	return out
}

func referenceKey(id, stixID string) string {
	if stixID != "" {
		return stixID
	}
	return id
}

func sortComponents(components []DataComponent) {
	sort.Slice(components, func(i, j int) bool {
		if components[i].Name != components[j].Name {
			return components[i].Name < components[j].Name
		}
		return components[i].ID < components[j].ID
	})
}
