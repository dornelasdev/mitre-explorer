package attack

import "sort"

// CollectUniqueTactics uses the supplied matrix order and display names, then
// appends unknown tactics in normalized alphabetical order.
func CollectUniqueTactics(techniques []Technique, attackOrder []string) []string {

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

// ValidateTactics separates present tactics by membership in the supplied order.
func ValidateTactics(techniques []Technique, tacticOrder []string) (known []string, unknown []string) {
	expected := make(map[string]struct{})
	for _, tactic := range tacticOrder {
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
