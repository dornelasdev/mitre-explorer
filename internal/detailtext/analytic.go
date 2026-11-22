// Package detailtext prepares shared content for terminal detail views.
package detailtext

import (
	"strings"

	"mitre-explorer/internal/attack"
)

type Section struct {
	Title   string
	Entries []string
}

// AnalyticSections returns the nonempty optional detail sections in source order.
func AnalyticSections(analytic attack.Analytic) []Section {
	sources := Section{Title: "Log Sources"}
	for _, source := range analytic.LogSources {
		name := strings.TrimSpace(source.Name)
		channel := strings.TrimSpace(source.Channel)
		switch {
		case name != "" && channel != "":
			sources.Entries = append(sources.Entries, name+" | Channel: "+channel)
		case name != "":
			sources.Entries = append(sources.Entries, name)
		case channel != "":
			sources.Entries = append(sources.Entries, "Channel: "+channel)
		case strings.TrimSpace(source.DataComponentRef) != "":
			sources.Entries = append(sources.Entries, strings.TrimSpace(source.DataComponentRef))
		}
	}

	elements := Section{Title: "Mutable Elements"}
	for _, element := range analytic.MutableElements {
		field := strings.TrimSpace(element.Field)
		description := strings.TrimSpace(element.Description)
		switch {
		case field != "" && description != "":
			elements.Entries = append(elements.Entries, field+": "+description)
		case field != "":
			elements.Entries = append(elements.Entries, field)
		case description != "":
			elements.Entries = append(elements.Entries, description)
		}
	}

	var sections []Section
	for _, section := range []Section{sources, elements} {
		if len(section.Entries) > 0 {
			sections = append(sections, section)
		}
	}
	return sections
}
