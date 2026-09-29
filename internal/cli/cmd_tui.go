package cli

import "mitre-explorer/internal/tui"

func (app *App) handleTUI(args []string) error {
	if len(args) != 1 {
		return invalidUsage("tui does not accept command-specific arguments")
	}

	return tui.Run(tui.Options{
		Matrix:    app.matrix.Name,
		CachePath: app.matrix.CachePath,
		Version:   app.version,
		Plain:     !app.useColor,
	})
}
