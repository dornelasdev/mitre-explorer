package attack

import (
	"sort"
	"strings"
)

type AssetFilters struct {
	Sector   string
	Platform string
}

// FilterAssets intersects exact sector and platform matches on the asset itself.
// Matching ignores case and surrounding whitespace and preserves input order.
func FilterAssets(assets []Asset, filters AssetFilters) []Asset {
	sector, platform := strings.TrimSpace(filters.Sector), strings.TrimSpace(filters.Platform)
	if sector == "" && platform == "" {
		return assets
	}
	matches := func(values []string, want string) bool {
		if want == "" {
			return true
		}
		for _, value := range values {
			if strings.EqualFold(strings.TrimSpace(value), want) {
				return true
			}
		}
		return false
	}
	var results []Asset
	for _, asset := range assets {
		if matches(asset.Sectors, sector) && matches(asset.Platforms, platform) {
			results = append(results, asset)
		}
	}
	return results
}

// AssetFilterValues lists nonblank sectors and platforms from asset metadata.
func AssetFilterValues(assets []Asset) (sectors, platforms []string) {
	collect := func(values func(Asset) []string) []string {
		var options []string
		seen := make(map[string]bool)
		for _, asset := range assets {
			for _, value := range values(asset) {
				value = strings.TrimSpace(value)
				key := strings.ToLower(value)
				if key != "" && !seen[key] {
					seen[key] = true
					options = append(options, value)
				}
			}
		}
		sort.Slice(options, func(i, j int) bool {
			return strings.ToLower(options[i]) < strings.ToLower(options[j])
		})
		return options
	}
	return collect(func(a Asset) []string { return a.Sectors }), collect(func(a Asset) []string { return a.Platforms })
}

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
