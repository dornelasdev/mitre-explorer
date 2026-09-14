package attack

import (
	"sort"
	"strings"
)

// SearchTechniques ranks name matches before description matches, then by ID.
func SearchTechniques(techniques []Technique, term string, nameOnly bool, limit int) []Technique {
	type searchHit struct {
		technique Technique
		score     int
	}

	var hits []searchHit
	term = strings.ToLower(strings.TrimSpace(term))
	if term == "" {
		return nil
	}

	for _, t := range techniques {
		if strings.Contains(strings.ToLower(t.Name), term) {
			hits = append(hits, searchHit{technique: t, score: 2})
		} else if !nameOnly && strings.Contains(strings.ToLower(t.Description), term) {
			hits = append(hits, searchHit{technique: t, score: 1})
		}
	}

	sort.Slice(hits, func(i, j int) bool {
		if hits[i].score != hits[j].score {
			return hits[i].score > hits[j].score
		}
		return hits[i].technique.ID < hits[j].technique.ID
	})

	out := make([]Technique, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.technique)
	}

	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}

	return out
}

// SearchDetectionNotes matches enriched detection text and sorts results by ID.
func SearchDetectionNotes(techniques []Technique, term string, limit int) []Technique {
	var out []Technique
	term = strings.ToLower(strings.TrimSpace(term))
	if term == "" {
		return out
	}

	for _, t := range techniques {
		if strings.Contains(strings.ToLower(t.DetectionNotes), term) {
			out = append(out, t)
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })

	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// EntitySearchResult identifies a matching non-technique entity.
type EntitySearchResult struct {
	Type string
	ID   string
	Name string
}

func appendEntitySearchResult(results []EntitySearchResult, entityType, id, name, description, term string) []EntitySearchResult {
	if strings.Contains(strings.ToLower(id), term) || strings.Contains(strings.ToLower(name), term) || strings.Contains(strings.ToLower(description), term) {
		return append(results, EntitySearchResult{
			Type: entityType,
			ID:   id,
			Name: name,
		})
	}
	return results
}

// SearchEntities searches IDs, names, and descriptions for a canonical target.
// The "all" target includes non-technique entities only.
func SearchEntities(cache CacheData, target, term string, limit int) []EntitySearchResult {
	var results []EntitySearchResult
	term = strings.ToLower(strings.TrimSpace(term))
	if term == "" {
		return nil
	}

	addGroups := target == "groups" || target == "all"
	addMitigations := target == "mitigations" || target == "all"
	addSoftware := target == "software" || target == "all"
	addCampaigns := target == "campaigns" || target == "all"
	addDetections := target == "detections" || target == "all"
	addAnalytics := target == "analytics" || target == "all"
	addDataComponents := target == "data-components" || target == "all"

	if addGroups {
		for _, g := range cache.Groups {
			results = appendEntitySearchResult(results, "group", g.ID, g.Name, g.Description, term)
		}
	}

	if addMitigations {
		for _, m := range cache.Mitigations {
			results = appendEntitySearchResult(results, "mitigation", m.ID, m.Name, m.Description, term)
		}
	}

	if addSoftware {
		for _, s := range cache.Softwares {
			results = appendEntitySearchResult(results, "software", s.ID, s.Name, s.Description, term)
		}
	}

	if addCampaigns {
		for _, c := range cache.Campaigns {
			results = appendEntitySearchResult(results, "campaign", c.ID, c.Name, c.Description, term)
		}
	}

	if addDetections {
		for _, d := range cache.DetectionStrategies {
			results = appendEntitySearchResult(results, "detection", d.ID, d.Name, d.Description, term)
		}
	}

	if addAnalytics {
		for _, a := range cache.Analytics {
			results = appendEntitySearchResult(results, "analytic", a.ID, a.Name, a.Description, term)
		}
	}

	if addDataComponents {
		for _, dc := range cache.DataComponents {
			results = appendEntitySearchResult(results, "data-component", dc.ID, dc.Name, dc.Description, term)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Type != results[j].Type {
			return results[i].Type < results[j].Type
		}
		if results[i].Name != results[j].Name {
			return results[i].Name < results[j].Name
		}
		return results[i].ID < results[j].ID
	})

	if limit > 0 && len(results) > limit {
		results = results[:limit]
	}

	return results
}
