package attack

import (
	"sort"
	"strings"
)

// ProcedureExample describes a documented use of a technique by a group, software,
// or campaign. Several examples may connect the same source and technique.
type ProcedureExample struct {
	StixID      string
	SourceType  string
	SourceID    string
	SourceName  string
	TechniqueID string
	Description string
	References  []ExternalReference
}

// ProcedureExamplesForTechnique returns direct uses relationships with procedure
// text, sorted by source type, source ID, and relationship ID. It does not inherit
// examples from parents or sub-techniques, or turn other relationships into uses.
func ProcedureExamplesForTechnique(cache CacheData, techniqueID string) []ProcedureExample {
	techniqueID = strings.TrimSpace(techniqueID)
	if techniqueID == "" {
		return nil
	}
	technique, found := FindTechniqueByID(cache.Techniques, techniqueID)
	if !found {
		return nil
	}
	type sourceKey struct{ kind, id string }
	sources := make(map[sourceKey]string)
	for _, group := range cache.Groups {
		if group.ID != "" {
			sources[sourceKey{"group", strings.ToLower(group.ID)}] = group.Name
		}
	}
	for _, software := range cache.Softwares {
		if software.ID != "" {
			sources[sourceKey{"software", strings.ToLower(software.ID)}] = software.Name
		}
	}
	for _, campaign := range cache.Campaigns {
		if campaign.ID != "" {
			sources[sourceKey{"campaign", strings.ToLower(campaign.ID)}] = campaign.Name
		}
	}
	var examples []ProcedureExample
	seen := make(map[string]struct{})
	for _, rel := range cache.Relationships {
		if rel.Type != "uses" || rel.TargetType != "technique" || !strings.EqualFold(rel.TargetID, technique.ID) || strings.TrimSpace(rel.Description) == "" {
			continue
		}
		name, found := sources[sourceKey{rel.SourceType, strings.ToLower(rel.SourceID)}]
		if !found {
			continue
		}
		if rel.StixID != "" {
			if _, duplicate := seen[rel.StixID]; duplicate {
				continue
			}
			seen[rel.StixID] = struct{}{}
		}
		examples = append(examples, ProcedureExample{
			StixID: rel.StixID, SourceType: rel.SourceType, SourceID: rel.SourceID,
			SourceName: name, TechniqueID: technique.ID, Description: rel.Description,
			References: append([]ExternalReference(nil), rel.References...),
		})
	}
	sort.SliceStable(examples, func(i, j int) bool {
		if examples[i].SourceType != examples[j].SourceType {
			return examples[i].SourceType < examples[j].SourceType
		}
		if examples[i].SourceID != examples[j].SourceID {
			return examples[i].SourceID < examples[j].SourceID
		}
		if examples[i].StixID != examples[j].StixID {
			return examples[i].StixID < examples[j].StixID
		}
		return examples[i].Description < examples[j].Description
	})
	return examples
}
