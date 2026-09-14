package attack

import (
	"sort"
	"strings"
)

// FindTechniqueByID matches a technique ID without case sensitivity.
func FindTechniqueByID(techniques []Technique, id string) (Technique, bool) {
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

// ListByTactic matches tactics with normalized separators and sorts by ID.
func ListByTactic(techniques []Technique, tactic string) []Technique {
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

// ListByPlatform matches a platform exactly without case sensitivity.
func ListByPlatform(techniques []Technique, platform string) []Technique {
	var out []Technique
	for _, t := range techniques {
		if containsSliceIgnoreCase(t.Platforms, platform) {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// FindGroup matches an ID, name, or alias without case sensitivity.
func FindGroup(cache CacheData, input string) (Group, bool) {
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

// FindMitigation matches an ID or name without case sensitivity.
func FindMitigation(cache CacheData, input string) (Mitigation, bool) {
	q := strings.TrimSpace(strings.ToLower(input))
	for _, m := range cache.Mitigations {
		if strings.ToLower(m.ID) == q || strings.ToLower(m.Name) == q {
			return m, true
		}
	}
	return Mitigation{}, false
}

// FindSoftware matches an ID, name, or alias without case sensitivity.
func FindSoftware(cache CacheData, input string) (Software, bool) {
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

// FindCampaign matches an ID, name, or alias without case sensitivity.
func FindCampaign(cache CacheData, input string) (Campaign, bool) {
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

// FindDetectionStrategy matches an external ID, STIX ID, or name.
func FindDetectionStrategy(cache CacheData, input string) (DetectionStrategy, bool) {
	q := strings.TrimSpace(strings.ToLower(input))

	for _, d := range cache.DetectionStrategies {
		if strings.ToLower(d.ID) == q || strings.ToLower(d.StixID) == q || strings.ToLower(d.Name) == q {
			return d, true
		}
	}
	return DetectionStrategy{}, false
}

// FindAnalytic matches an external ID, STIX ID, or name.
func FindAnalytic(cache CacheData, input string) (Analytic, bool) {
	q := strings.TrimSpace(strings.ToLower(input))

	for _, a := range cache.Analytics {
		if strings.ToLower(a.ID) == q || strings.ToLower(a.StixID) == q || strings.ToLower(a.Name) == q {
			return a, true
		}
	}

	return Analytic{}, false
}

// TechniqueFilters selects techniques matching every supplied filter.
type TechniqueFilters struct {
	Tactic        string
	Platform      string
	DataComponent string
}

// FilterTechniques resolves components before intersecting tactic/platform
// filters. Without filters it preserves the original cache order.
func FilterTechniques(cache CacheData, filters TechniqueFilters) []Technique {
	results := cache.Techniques
	if filters.DataComponent != "" {
		results = TechniquesByDataComponent(cache, filters.DataComponent)
	}
	if filters.Tactic != "" {
		results = ListByTactic(results, filters.Tactic)
	}
	if filters.Platform != "" {
		results = ListByPlatform(results, filters.Platform)
	}
	return results
}
