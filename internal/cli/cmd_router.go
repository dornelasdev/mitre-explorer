package cli

func (app *App) applyGlobalOptions(args []string) ([]string, error) {
	matrix, useColor := app.matrix, app.useColor
	filtered := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--plain":
			useColor = false
		case "--matrix":
			value, err := optionValue(args, i)
			if err != nil {
				return nil, err
			}
			selected, err := matrixFor(value)
			if err != nil {
				return nil, invalidUsage("%v", err)
			}
			matrix = selected
			i++
		default:
			filtered = append(filtered, args[i])
		}
	}
	app.matrix, app.useColor = matrix, useColor
	return filtered, nil
}

func (app *App) runCommand(args []string) int {
	if len(args) == 0 {
		return app.reportError(invalidUsage("a command is required"))
	}
	filtered, err := app.applyGlobalOptions(args)
	if err != nil {
		return app.reportError(err, args...)
	}
	args = filtered
	// Global-options-only input is a valid manual session configuration change.
	if len(args) == 0 {
		return 0
	}
	return app.reportError(app.dispatchCommand(args))
}

func (app *App) dispatchCommand(args []string) error {
	if len(args) == 0 {
		return invalidUsage("a command is required")
	}
	switch args[0] {
	case "update":
		return app.handleUpdate(args)
	case "status":
		return app.handleStatus(args)
	case "export":
		return app.handleExport(args)
	case "help":
		return app.handleHelp(args)
	case "tui":
		return app.handleTUI(args)
	case "search":
		return app.handleSearch(args)
	case "show":
		return app.handleShow(args)
	case "list":
		return app.handleList(args)
	case "group":
		return app.handleGroup(args)
	case "mitigation":
		return app.handleMitigation(args)
	case "software":
		return app.handleSoftware(args)
	case "campaign":
		return app.handleCampaign(args)
	case "detection":
		return app.handleDetection(args)
	case "analytic":
		return app.handleAnalytic(args)
	default:
		return invalidUsage("unknown command: %s", args[0])
	}
}
