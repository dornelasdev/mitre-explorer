package cli

import "mitre-explorer/internal/tui"

func (app *App) handleTUI(args []string) error {
	if len(args) != 1 {
		return invalidUsage("tui does not accept command-specific arguments")
	}

	return tui.Run(tui.Options{
		Matrix:      app.matrix.Name,
		CachePath:   app.matrix.CachePath,
		TacticOrder: append([]string(nil), app.matrix.TacticOrder...),
		Matrices: []tui.MatrixOption{
			matrixTUIOption(enterpriseMatrix),
			matrixTUIOption(mobileMatrix),
			matrixTUIOption(icsMatrix),
		},
		Version: app.version,
		Plain:   !app.useColor,
	})
}

func matrixTUIOption(matrix MatrixConfig) tui.MatrixOption {
	return tui.MatrixOption{
		Name:        matrix.Name,
		CachePath:   matrix.CachePath,
		TacticOrder: append([]string(nil), matrix.TacticOrder...),
	}
}
