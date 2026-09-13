package main

import (
	"sort"
	"strings"

	"mitre-explorer/internal/attack"
)

func containsIgnoreCase(text, term string) bool {
	return strings.Contains(strings.ToLower(text), strings.ToLower(term))
}

func searchTechniques(techniques []attack.Technique, term string, nameOnly bool, limit int) []attack.Technique {
	type searchHit struct {
		technique attack.Technique
		score     int
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

	out := make([]attack.Technique, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.technique)
	}

	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}

	return out
}

func findTechniqueByID(techniques []attack.Technique, id string) (attack.Technique, bool) {
	for _, t := range techniques {
		if strings.EqualFold(t.ID, id) {
			return t, true
		}
	}
	return attack.Technique{}, false
}

func containsSliceIgnoreCase(values []string, target string) bool {
	for _, v := range values {
		if strings.EqualFold(v, target) {
			return true
		}
	}
	return false
}

func listByTactic(techniques []attack.Technique, tactic string) []attack.Technique {
	var out []attack.Technique
	for _, t := range techniques {
		if containsTacticNormalized(t.Tactics, tactic) {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func normalizeTactic(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.ReplaceAll(s, "-", " ")
	s = strings.ReplaceAll(s, "_", " ")
	return s
}

func containsTacticNormalized(values []string, target string) bool {
	targetKey := normalizeTactic(target)
	for _, v := range values {
		if normalizeTactic(v) == targetKey {
			return true
		}
	}
	return false
}

func listByPlatform(techniques []attack.Technique, platform string) []attack.Technique {
	var out []attack.Technique
	for _, t := range techniques {
		if containsSliceIgnoreCase(t.Platforms, platform) {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func collectUniqueTactics(techniques []attack.Technique) []string {
	// Active ATT&CK matrix tactic order
	attackOrder := activeMatrix.TacticOrder

	orderIndex := make(map[string]int, len(attackOrder))
	displayName := make(map[string]string, len(attackOrder))
	for i, t := range attackOrder {
		k := normalizeTactic(t)
		orderIndex[k] = i
		displayName[k] = t
	}

	seen := make(map[string]struct{})
	type tacticItem struct {
		display string
		key     string
	}
	var items []tacticItem

	for _, tech := range techniques {
		for _, t := range tech.Tactics {
			key := normalizeTactic(t)
			if key == "" {
				continue
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}

			display := t
			if v, ok := displayName[key]; ok {
				display = v
			}

			items = append(items, tacticItem{
				display: display,
				key:     key,
			})
		}
	}

	sort.Slice(items, func(i, j int) bool {
		oi, iok := orderIndex[items[i].key]
		oj, jok := orderIndex[items[j].key]

		if iok && jok {
			return oi < oj
		}
		if iok != jok {
			return iok
		}
		return items[i].key < items[j].key

	})
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.display)
	}
	return out
}

func matrixTacticValidation(techniques []attack.Technique) (known []string, unknown []string) {
	expected := make(map[string]struct{})
	for _, tactic := range activeMatrix.TacticOrder {
		expected[normalizeTactic(tactic)] = struct{}{}
	}

	seenKnown := make(map[string]struct{})
	seenUnknown := make(map[string]struct{})

	for _, technique := range techniques {
		for _, tactic := range technique.Tactics {
			key := normalizeTactic(tactic)
			if key == "" {
				continue
			}

			if _, ok := expected[key]; ok {
				if _, seen := seenKnown[key]; seen {
					continue
				}
				seenKnown[key] = struct{}{}
				known = append(known, tactic)
				continue
			}

			if _, seen := seenUnknown[key]; seen {
				continue
			}
			seenUnknown[key] = struct{}{}
			unknown = append(unknown, tactic)
		}
	}

	sort.Slice(known, func(i, j int) bool { return normalizeTactic(known[i]) < normalizeTactic(known[j]) })
	sort.Slice(unknown, func(i, j int) bool { return normalizeTactic(unknown[i]) < normalizeTactic(unknown[j]) })
	return known, unknown
}

func findGroup(cache attack.CacheData, input string) (attack.Group, bool) {
	q := strings.TrimSpace(strings.ToLower(input))

	for _, g := range cache.Groups {
		if strings.ToLower(g.ID) == q || strings.ToLower(g.Name) == q {
			return g, true
		}
		for _, a := range g.Aliases {
			if strings.ToLower(a) == q {
				return g, true
			}
		}
	}
	return attack.Group{}, false
}

func techniquesUsedByGroup(cache attack.CacheData, groupID string) []attack.Technique {
	techByID := make(map[string]attack.Technique, len(cache.Techniques))
	for _, t := range cache.Techniques {
		techByID[t.ID] = t
	}

	seen := make(map[string]struct{})
	var out []attack.Technique

	for _, rel := range cache.Relationships {
		if rel.Type != "uses" {
			continue
		}
		if rel.SourceType != "group" || rel.TargetType != "technique" {
			continue
		}
		if !strings.EqualFold(rel.SourceID, groupID) {
			continue
		}
		if _, ok := seen[rel.TargetID]; ok {
			continue
		}
		seen[rel.TargetID] = struct{}{}

		if t, ok := techByID[rel.TargetID]; ok {
			out = append(out, t)
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func findMitigation(cache attack.CacheData, input string) (attack.Mitigation, bool) {
	q := strings.TrimSpace(strings.ToLower(input))
	for _, m := range cache.Mitigations {
		if strings.ToLower(m.ID) == q || strings.ToLower(m.Name) == q {
			return m, true
		}
	}
	return attack.Mitigation{}, false
}

func techniquesMitigatedBy(cache attack.CacheData, mitigationID string) []attack.Technique {
	techByID := make(map[string]attack.Technique, len(cache.Techniques))
	for _, t := range cache.Techniques {
		techByID[t.ID] = t
	}

	seen := make(map[string]struct{})
	var out []attack.Technique

	for _, rel := range cache.Relationships {
		if rel.Type != "mitigates" {
			continue
		}
		if rel.SourceType != "mitigation" || rel.TargetType != "technique" {
			continue
		}
		if !strings.EqualFold(rel.SourceID, mitigationID) {
			continue
		}
		if _, ok := seen[rel.TargetID]; ok {
			continue
		}
		seen[rel.TargetID] = struct{}{}

		if t, ok := techByID[rel.TargetID]; ok {
			out = append(out, t)
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func findSoftware(cache attack.CacheData, input string) (attack.Software, bool) {
	q := strings.TrimSpace(strings.ToLower(input))

	for _, s := range cache.Softwares {
		if strings.ToLower(s.ID) == q || strings.ToLower(s.Name) == q {
			return s, true
		}
		for _, a := range s.Aliases {
			if strings.ToLower(a) == q {
				return s, true
			}
		}
	}
	return attack.Software{}, false
}

func techniquesUsedBySoftware(cache attack.CacheData, softwareID string) []attack.Technique {
	techByID := make(map[string]attack.Technique, len(cache.Techniques))
	for _, t := range cache.Techniques {
		techByID[t.ID] = t
	}

	seen := make(map[string]struct{})
	var out []attack.Technique

	for _, rel := range cache.Relationships {
		if rel.Type != "uses" {
			continue
		}
		if rel.SourceType != "software" || rel.TargetType != "technique" {
			continue
		}
		if !strings.EqualFold(rel.SourceID, softwareID) {
			continue
		}
		if _, ok := seen[rel.TargetID]; ok {
			continue
		}
		seen[rel.TargetID] = struct{}{}

		if t, ok := techByID[rel.TargetID]; ok {
			out = append(out, t)
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func findCampaign(cache attack.CacheData, input string) (attack.Campaign, bool) {
	q := strings.TrimSpace(strings.ToLower(input))

	for _, c := range cache.Campaigns {
		if strings.ToLower(c.ID) == q || strings.ToLower(c.Name) == q {
			return c, true
		}
		for _, a := range c.Aliases {
			if strings.ToLower(a) == q {
				return c, true
			}
		}
	}
	return attack.Campaign{}, false
}

func techniquesUsedByCampaign(cache attack.CacheData, campaignID string) []attack.Technique {
	techByID := make(map[string]attack.Technique, len(cache.Techniques))
	for _, t := range cache.Techniques {
		techByID[t.ID] = t
	}

	seen := make(map[string]struct{})
	var out []attack.Technique

	for _, rel := range cache.Relationships {
		if rel.Type != "uses" {
			continue
		}
		if rel.SourceType != "campaign" || rel.TargetType != "technique" {
			continue
		}
		if !strings.EqualFold(rel.SourceID, campaignID) {
			continue
		}
		if _, ok := seen[rel.TargetID]; ok {
			continue
		}
		seen[rel.TargetID] = struct{}{}

		if t, ok := techByID[rel.TargetID]; ok {
			out = append(out, t)
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func listByDataComponent(techniques []attack.Technique, component string) []attack.Technique {
	var out []attack.Technique
	for _, t := range techniques {
		if containsSliceIgnoreCase(t.DataComponents, component) {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func searchDetectionNotes(techniques []attack.Technique, term string, limit int) []attack.Technique {
	var out []attack.Technique
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

func techniquesByDataComponent(cache attack.CacheData, componentInput string) []attack.Technique {
	q := strings.TrimSpace(strings.ToLower(componentInput))
	if q == "" {
		return nil
	}

	componentIDs := make(map[string]struct{})
	for _, dc := range cache.DataComponents {
		if strings.Contains(strings.ToLower(dc.Name), q) || strings.EqualFold(dc.ID, componentInput) || strings.EqualFold(dc.StixID, componentInput) {
			componentIDs[dc.ID] = struct{}{}
			componentIDs[dc.StixID] = struct{}{}
		}
	}

	techByID := make(map[string]attack.Technique, len(cache.Techniques))
	for _, t := range cache.Techniques {
		techByID[t.ID] = t
	}

	seen := make(map[string]struct{})
	var out []attack.Technique

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

func findDetectionStrategy(cache attack.CacheData, input string) (attack.DetectionStrategy, bool) {
	q := strings.TrimSpace(strings.ToLower(input))

	for _, d := range cache.DetectionStrategies {
		if strings.ToLower(d.ID) == q || strings.ToLower(d.StixID) == q || strings.ToLower(d.Name) == q {
			return d, true
		}
	}
	return attack.DetectionStrategy{}, false
}

func techniquesDetectedByStrategy(cache attack.CacheData, detectionID string) []attack.Technique {
	techByID := make(map[string]attack.Technique, len(cache.Techniques))
	for _, t := range cache.Techniques {
		techByID[t.ID] = t
	}

	seen := make(map[string]struct{})
	var out []attack.Technique

	for _, rel := range cache.Relationships {
		if rel.Type != "detects" {
			continue
		}
		if rel.SourceType != "detection_strategy" || rel.TargetType != "technique" {
			continue
		}
		if !strings.EqualFold(rel.SourceID, detectionID) {
			continue
		}
		if _, ok := seen[rel.TargetID]; ok {
			continue
		}
		seen[rel.TargetID] = struct{}{}

		if t, ok := techByID[rel.TargetID]; ok {
			out = append(out, t)
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
func findAnalytic(cache attack.CacheData, input string) (attack.Analytic, bool) {
	q := strings.TrimSpace(strings.ToLower(input))

	for _, a := range cache.Analytics {
		if strings.ToLower(a.ID) == q || strings.ToLower(a.StixID) == q || strings.ToLower(a.Name) == q {
			return a, true
		}
	}

	return attack.Analytic{}, false
}

func analyticsByDetectionStrategy(cache attack.CacheData, detectionID string) []attack.Analytic {
	d, found := findDetectionStrategy(cache, detectionID)
	if !found {
		return nil
	}

	analyticByID := make(map[string]attack.Analytic, len(cache.Analytics))
	for _, a := range cache.Analytics {
		analyticByID[a.ID] = a
		analyticByID[a.StixID] = a
	}

	seen := make(map[string]struct{})
	var out []attack.Analytic

	for _, ref := range d.Analytics {
		a, ok := analyticByID[ref]
		if !ok {
			continue
		}
		if _, exists := seen[a.StixID]; exists {
			continue
		}

		seen[a.StixID] = struct{}{}
		out = append(out, a)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func dataComponentsByAnalytic(cache attack.CacheData, analyticID string) []attack.DataComponent {
	a, found := findAnalytic(cache, analyticID)
	if !found {
		return nil
	}

	componentByID := make(map[string]attack.DataComponent, len(cache.DataComponents))
	for _, dc := range cache.DataComponents {
		componentByID[dc.ID] = dc
		componentByID[dc.StixID] = dc
	}

	seen := make(map[string]struct{})
	var out []attack.DataComponent

	for _, ref := range a.DataComponents {
		dc, ok := componentByID[ref]
		if !ok {
			continue
		}

		if _, exists := seen[dc.StixID]; exists {
			continue
		}

		seen[dc.StixID] = struct{}{}
		out = append(out, dc)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func dataComponentsByDetectionStrategy(cache attack.CacheData, detectionID string) []attack.DataComponent {
	analytics := analyticsByDetectionStrategy(cache, detectionID)

	seen := make(map[string]struct{})
	var out []attack.DataComponent

	for _, a := range analytics {
		components := dataComponentsByAnalytic(cache, a.ID)

		for _, dc := range components {
			if _, exists := seen[dc.StixID]; exists {
				continue
			}

			seen[dc.StixID] = struct{}{}
			out = append(out, dc)
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
