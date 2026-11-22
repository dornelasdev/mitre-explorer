package cli

import (
	"fmt"
	"strings"

	"mitre-explorer/internal/attack"
	"mitre-explorer/internal/detailtext"
)

func (app *App) printAnalyticDetails(a attack.Analytic, componentCount int, issues []attack.ReferenceIssue) {
	app.printSection("Analytic Details")
	fields := []DetailField{{"ID:", a.ID}, {"Name:", a.Name}}
	if platforms := strings.Join(a.Platforms, ", "); strings.TrimSpace(platforms) != "" {
		fields = append(fields, DetailField{"Platforms:", platforms})
	}
	fields = append(fields,
		DetailField{"Data Components:", mappingCount(componentCount, len(issues) > 0)},
		DetailField{"Description:", a.Description},
	)
	app.printDetails(fields)
	app.printReferenceIssues(issues)

	for _, section := range detailtext.AnalyticSections(a) {
		app.printSubsection(section.Title)
		for _, entry := range section.Entries {
			fmt.Fprintf(app.out, "  - %s\n", strings.ReplaceAll(entry, "\n", "\n    "))
		}
	}
}
