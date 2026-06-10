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

func collectUniqueTactics(techniques []Technique) []string {
	// ATT&CK Enterprise tactic order
	attackOrder := []string{
		"Reconnaissance",
		"Resource Development",
		"Initial Access",
		"Execution",
		"Persistence",
		"Privilege Escalation",
		"Stealth",
		"Defense Impairment",
		"Credential Access",
		"Discovery",
		"Lateral Movement",
		"Collection",
		"Command and Control",
		"Exfiltration",
		"Impact",
	}

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

func findGroup(cache CacheData, input string) (Group, bool) {
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
	return Group{}, false
}

func techniquesUsedByGroup(cache CacheData, groupID string) []Technique {
	techByID := make(map[string]Technique, len(cache.Techniques))
	for _, t := range cache.Techniques {
		techByID[t.ID] = t
	}

	seen := make(map[string]struct{})
	var out []Technique

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

func findMitigation(cache CacheData, input string) (Mitigation, bool) {
	q := strings.TrimSpace(strings.ToLower(input))
	for _, m := range cache.Mitigations {
		if strings.ToLower(m.ID) == q || strings.ToLower(m.Name) == q {
			return m, true
		}
	}
	return Mitigation{}, false
}

func techniquesMitigatedBy(cache CacheData, mitigationID string) []Technique {
	techByID := make(map[string]Technique, len(cache.Techniques))
	for _, t := range cache.Techniques {
		techByID[t.ID] = t
	}

	seen := make(map[string]struct{})
	var out []Technique

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

func findSoftware(cache CacheData, input string) (Software, bool) {
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
	return Software{}, false
}

func techniquesUsedBySoftware(cache CacheData, softwareID string) []Technique {
	techByID := make(map[string]Technique, len(cache.Techniques))
	for _, t := range cache.Techniques {
		techByID[t.ID] = t
	}

	seen := make(map[string]struct{})
	var out []Technique

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

func findCampaign(cache CacheData, input string) (Campaign, bool) {
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
	return Campaign{}, false
}

func techniquesUsedByCampaign(cache CacheData, campaignID string) []Technique {
	techByID := make(map[string]Technique, len(cache.Techniques))
	for _, t := range cache.Techniques {
		techByID[t.ID] = t
	}

	seen := make(map[string]struct{})
	var out []Technique

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

func listByDataComponent(techniques []Technique, component string) []Technique {
	var out []Technique
	for _, t := range techniques {
		if containsSliceIgnoreCase(t.DataComponents, component) {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func searchDetectionNotes(techniques []Technique, term string, limit int) []Technique {
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

func techniquesByDataComponent(cache CacheData, componentInput string) []Technique {
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

	techByID := make(map[string]Technique, len(cache.Techniques))
	for _, t := range cache.Techniques {
		techByID[t.ID] = t
	}

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

func findDetectionStrategy(cache CacheData, input string) (DetectionStrategy, bool) {
	q := strings.TrimSpace(strings.ToLower(input))

	for _, d := range cache.DetectionStrategies {
		if strings.ToLower(d.ID) == q || strings.ToLower(d.StixID) == q || strings.ToLower(d.Name) == q {
			return d, true
		}
	}
	return DetectionStrategy{}, false
}

func techniquesDetectedByStrategy(cache CacheData, detectionID string) []Technique {
	techByID := make(map[string]Technique, len(cache.Techniques))
	for _, t := range cache.Techniques {
		techByID[t.ID] = t
	}

	seen := make(map[string]struct{})
	var out []Technique

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
func findAnalytic(cache CacheData, input string) (Analytic, bool) {
	q := strings.TrimSpace(strings.ToLower(input))

	for _, a := range cache.Analytics {
		if strings.ToLower(a.ID) == q || strings.ToLower(a.StixID) == q || strings.ToLower(a.Name) == q {
			return a, true
		}
	}

	return Analytic{}, false
}

func analyticsByDetectionStrategy(cache CacheData, detectionID string) []Analytic {
	d, found := findDetectionStrategy(cache, detectionID)
	if !found {
		return nil
	}

	analyticByID := make(map[string]Analytic, len(cache.Analytics))
	for _, a := range cache.Analytics {
		analyticByID[a.ID] = a
		analyticByID[a.StixID] = a
	}

	seen := make(map[string]struct{})
	var out []Analytic

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
