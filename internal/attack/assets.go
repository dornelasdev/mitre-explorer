package attack

import "strings"

// FindAsset matches an ATT&CK ID, STIX ID, or exact name without case sensitivity.
func FindAsset(cache CacheData, input string) (Asset, bool) {
	input = strings.TrimSpace(input)
	if input != "" {
		for _, asset := range cache.Assets {
			if strings.EqualFold(asset.ID, input) || strings.EqualFold(asset.StixID, input) || strings.EqualFold(asset.Name, input) {
				return asset, true
			}
		}
	}
	return Asset{}, false
}

// TechniquesTargetingAsset returns direct targets relationships to the asset,
// sorted by technique ID. The asset can be given by ID or name.
func TechniquesTargetingAsset(cache CacheData, input string) []Technique {
	asset, found := FindAsset(cache, input)
	if !found {
		return nil
	}
	refs := make(map[string]struct{})
	for _, rel := range cache.Relationships {
		if !isAssetTarget(rel) {
			continue
		}
		if strings.EqualFold(rel.TargetID, asset.ID) || strings.EqualFold(rel.TargetID, asset.StixID) {
			refs[strings.ToLower(rel.SourceID)] = struct{}{}
		}
	}
	if len(refs) == 0 {
		return nil
	}
	return resolveRelationshipEntities(refs, cache.Techniques,
		func(technique Technique) (string, string) { return technique.ID, "" })
}

// AssetsTargetedByTechnique returns assets explicitly linked to this exact
// technique or sub-technique, sorted by asset ID.
func AssetsTargetedByTechnique(cache CacheData, techniqueID string) []Asset {
	technique, found := FindTechniqueByID(cache.Techniques, strings.TrimSpace(techniqueID))
	if !found || technique.ID == "" {
		return nil
	}
	refs := make(map[string]struct{})
	for _, rel := range cache.Relationships {
		if isAssetTarget(rel) && strings.EqualFold(rel.SourceID, technique.ID) {
			refs[strings.ToLower(rel.TargetID)] = struct{}{}
		}
	}
	if len(refs) == 0 {
		return nil
	}
	return resolveRelationshipEntities(refs, cache.Assets,
		func(asset Asset) (string, string) { return asset.ID, asset.StixID })
}

func isAssetTarget(rel Relationship) bool {
	return rel.Type == "targets" && rel.SourceType == "technique" && rel.TargetType == "asset" &&
		rel.SourceID != "" && rel.TargetID != ""
}
