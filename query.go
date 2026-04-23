package main

import (
	"sort"
	"strings"
)

func containsIgnoreCase(text, term string) bool {
	return strings.Contains(strings.ToLower(text), strings.ToLower(term))
}

func searchTechniques(techniques []Technique, term string, nameOnly bool, limit int) []Technique {
	type searchHit struct {
		technique Technique
		score int
	}

	var hits []searchHit

	for _, t := range techniques {
		nameMatch := containsIgnoreCase(t.Name, term)
		descMatch := containsIgnoreCase(t.Description, term)

		if nameOnly {
			if nameMatch {
				hits = append(hits, searchHit{technique: t, score: 2})
			}
			continue
		}

		if nameMatch {
			hits = append(hits, searchHit{technique: t, score: 2})
		} else if descMatch {
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

func findTechniqueByID(techniques []Technique, id string) (Technique, bool) {
	for _, t := range techniques {
		if strings.EqualFold(t.ID, id) {
			return t, true
		}
	}
	return Technique{}, false
}

func containsSliceIgnoreCase(values []string, target string) bool {
	for _, v := range values {
		if strings.EqualFold(v, target) {
			return true
		}
	}
	return false
}

func listByTactic(techniques []Technique, tactic string) []Technique {
	var out []Technique
	for _, t := range techniques {
		if containsSliceIgnoreCase(t.Tactics, tactic) {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func listByPlatform(techniques []Technique, platform string) []Technique {
	var out []Technique
	for _, t := range techniques {
		if containsSliceIgnoreCase(t.Platforms, platform) {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
