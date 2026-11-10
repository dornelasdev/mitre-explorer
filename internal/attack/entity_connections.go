package attack

import "strings"

// SoftwareUsedByGroup returns directly linked software sorted by ID.
func SoftwareUsedByGroup(cache CacheData, groupID string) []Software {
	return connectedEntities(cache, groupID, connectionSpec{"uses", "group", "software", false}, cache.Softwares,
		func(software Software) (string, string) { return software.ID, "" })
}

// GroupsUsingSoftware returns groups with a direct uses relationship, sorted by ID.
func GroupsUsingSoftware(cache CacheData, softwareID string) []Group {
	return connectedEntities(cache, softwareID, connectionSpec{"uses", "group", "software", true}, cache.Groups,
		func(group Group) (string, string) { return group.ID, "" })
}

// SoftwareUsedByCampaign returns directly linked software sorted by ID.
func SoftwareUsedByCampaign(cache CacheData, campaignID string) []Software {
	return connectedEntities(cache, campaignID, connectionSpec{"uses", "campaign", "software", false}, cache.Softwares,
		func(software Software) (string, string) { return software.ID, "" })
}

// CampaignsUsingSoftware returns campaigns with a direct uses relationship,
// sorted by ID.
func CampaignsUsingSoftware(cache CacheData, softwareID string) []Campaign {
	return connectedEntities(cache, softwareID, connectionSpec{"uses", "campaign", "software", true}, cache.Campaigns,
		func(campaign Campaign) (string, string) { return campaign.ID, "" })
}

// CampaignsAttributedToGroup returns directly attributed campaigns sorted by ID.
func CampaignsAttributedToGroup(cache CacheData, groupID string) []Campaign {
	return connectedEntities(cache, groupID, connectionSpec{"attributed-to", "campaign", "group", true}, cache.Campaigns,
		func(campaign Campaign) (string, string) { return campaign.ID, "" })
}

// GroupsForCampaign returns groups the campaign is directly attributed to,
// sorted by ID. Attribution is not inferred from shared software or techniques.
func GroupsForCampaign(cache CacheData, campaignID string) []Group {
	return connectedEntities(cache, campaignID, connectionSpec{"attributed-to", "campaign", "group", false}, cache.Groups,
		func(group Group) (string, string) { return group.ID, "" })
}

type connectionSpec struct {
	kind, sourceType, targetType string
	incoming                     bool
}

func connectedEntities[T any](cache CacheData, entityID string, spec connectionSpec, entities []T, ids func(T) (string, string)) []T {
	entityID = strings.TrimSpace(entityID)
	anchorType := spec.sourceType
	if spec.incoming {
		anchorType = spec.targetType
	}
	if entityID == "" || !connectionAnchorExists(cache, anchorType, entityID) {
		return nil
	}

	references := make(map[string]struct{})
	for _, rel := range cache.Relationships {
		if rel.Type != spec.kind || rel.SourceType != spec.sourceType || rel.TargetType != spec.targetType {
			continue
		}
		anchorID, relatedID := rel.SourceID, rel.TargetID
		if spec.incoming {
			anchorID, relatedID = rel.TargetID, rel.SourceID
		}
		if strings.EqualFold(anchorID, entityID) && relatedID != "" {
			references[strings.ToLower(relatedID)] = struct{}{}
		}
	}
	if len(references) == 0 {
		return nil
	}
	return resolveRelationshipEntities(references, entities, ids)
}

func connectionAnchorExists(cache CacheData, kind, id string) bool {
	switch kind {
	case "group":
		for _, group := range cache.Groups {
			if strings.EqualFold(group.ID, id) {
				return true
			}
		}
	case "software":
		for _, software := range cache.Softwares {
			if strings.EqualFold(software.ID, id) {
				return true
			}
		}
	case "campaign":
		for _, campaign := range cache.Campaigns {
			if strings.EqualFold(campaign.ID, id) {
				return true
			}
		}
	}
	return false
}
