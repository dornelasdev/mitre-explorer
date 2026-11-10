package cli

import (
	"fmt"
	"strconv"
	"strings"

	"mitre-explorer/internal/attack"
)

func (app *App) printProcedures(examples []attack.ProcedureExample) {
	app.printSubsection("Procedure Examples")
	if len(examples) == 0 {
		fmt.Fprintln(app.out, "No procedure examples found for this technique in this cache.")
		return
	}
	fmt.Fprintf(app.out, "Found %d procedure example(s)\n", len(examples))
	for index, example := range examples {
		app.printProcedureDetails(example, index+1)
	}
}

func (app *App) printProcedureDetails(example attack.ProcedureExample, number int) {
	app.printSubsection(fmt.Sprintf("Procedure %d: %s (%s)", number, example.SourceName, example.SourceID))
	app.printDetails([]DetailField{
		{"Source type:", example.SourceType},
		{"Technique:", example.TechniqueID},
		{"Relationship:", example.StixID},
		{"Description:", example.Description},
	})
	fmt.Fprintln(app.out, app.label("Citations:"))
	if len(example.References) == 0 {
		fmt.Fprintln(app.out, "No citation metadata supplied.")
	}
	for index, reference := range example.References {
		fmt.Fprintf(app.out, "[%d] %s\n", index+1, reference.SourceName)
		if reference.Description != "" {
			fmt.Fprintln(app.out, "  "+reference.Description)
		}
		if reference.URL != "" {
			fmt.Fprintln(app.out, "  URL: "+reference.URL)
		}
		if reference.ExternalID != "" {
			fmt.Fprintln(app.out, "  External ID: "+reference.ExternalID)
		}
	}
}

func (app *App) runGuidedProcedures(examples []attack.ProcedureExample) (bool, error) {
	if len(examples) == 0 {
		app.printProcedures(examples)
		return false, nil
	}
	rows := make([][]string, 0, len(examples))
	for index, example := range examples {
		rows = append(rows, []string{strconv.Itoa(index + 1), example.SourceType, example.SourceID, example.SourceName})
	}
	for {
		app.printSubsection("Procedure Examples")
		app.printEntityTable([]string{"#", "Type", "ID", "Source"}, rows, []int{4, 10, 12, 56})
		fmt.Fprintln(app.out, "Select a procedure number, [Enter/b] technique mappings, or [q] guided menu.")
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
		if err != nil || choice < 1 || choice > len(examples) {
			app.printInvalidSelection()
			continue
		}
		app.printProcedureDetails(examples[choice-1], choice)
		for {
			fmt.Fprintln(app.out, "[Enter/b] Back to procedures  [q] Guided menu")
			fmt.Fprint(app.out, "> ")
			next, err := readLine(app.reader)
			if err != nil {
				return false, err
			}
			if strings.EqualFold(next, "q") {
				return true, nil
			}
			if next == "" || strings.EqualFold(next, "b") {
				break
			}
			app.printInvalidSelection()
		}
	}
}
