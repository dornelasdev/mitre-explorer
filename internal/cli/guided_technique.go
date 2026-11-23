package cli

import (
	"fmt"
	"strconv"
	"strings"

	"mitre-explorer/internal/attack"
)

// The bool requests the guided menu; Enter/b returns to the technique list.
func (app *App) runGuidedTechnique(cache attack.CacheData, technique attack.Technique) (bool, error) {
	app.printSection("Technique Details")
	app.printTechniqueDetails(technique)
	kinds := app.techniqueMappings()
	for {
		fmt.Fprintln(app.out, "\nTechnique mappings:")
		for index, kind := range kinds {
			fmt.Fprintf(app.out, "  [%d] View %s\n", index+1, strings.ToLower(kind.title))
		}
		fmt.Fprintln(app.out, "  [Enter/b] Back to the technique list")
		fmt.Fprintln(app.out, "  [q] Return to guided menu")
		fmt.Fprint(app.out, "> ")
		input, err := readLine(app.reader)
		if err != nil {
			return false, err
		}
		switch strings.ToLower(input) {
		case "", "b":
			return false, nil
		case "q":
			return true, nil
		}
		choice, err := strconv.Atoi(input)
		if err != nil || choice < 1 || choice > len(kinds) {
			app.printInvalidSelection()
			continue
		}
		target := kinds[choice-1].target
		if target == "procedures" {
			menu, err := app.runGuidedProcedures(attack.ProcedureExamplesForTechnique(cache, technique.ID))
			if menu || err != nil {
				return menu, err
			}
		} else {
			app.printTechniqueEntities(cache, technique.ID, target)
		}
	}
}
