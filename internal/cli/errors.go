package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"mitre-explorer/internal/attack"
)

type usageError struct {
	message string
}

func (err *usageError) Error() string { return err.message }

func invalidUsage(format string, args ...any) error {
	return &usageError{message: fmt.Sprintf(format, args...)}
}

func (app *App) reportError(err error, args ...string) int {
	if err == nil {
		return 0
	}
	useColor := app.useColor
	for _, arg := range args {
		if arg == "--plain" {
			useColor = false
		}
	}
	message := "Error: " + err.Error()
	if useColor {
		message = cRed + message + cReset
	}
	fmt.Fprintln(app.errOut, message)
	var usage *usageError
	if errors.As(err, &usage) {
		fmt.Fprintln(app.errOut, "Use: go run . help <command>")
		return 2
	}
	return 1
}

// Option values must not consume the next flag or an empty argument.
func optionValue(args []string, index int) (string, error) {
	if index+1 >= len(args) || strings.TrimSpace(args[index+1]) == "" || strings.HasPrefix(args[index+1], "-") {
		return "", invalidUsage("%s requires a value", args[index])
	}
	return args[index+1], nil
}

func requireOperand(value, name string) error {
	if strings.TrimSpace(value) == "" || strings.HasPrefix(value, "-") {
		return invalidUsage("%s is required before options", name)
	}
	return nil
}

func (app *App) loadCacheForCommand() (attack.CacheData, error) {
	cache, err := attack.LoadCacheData(app.matrix.CachePath)
	if err != nil {
		return attack.CacheData{}, fmt.Errorf("load %s cache (run: go run . update --matrix %s): %w", app.activeMatrixName(), app.activeMatrixName(), err)
	}
	return cache, nil
}

func (app *App) loadUpdateMetaForCommand() (attack.UpdateMeta, error) {
	meta, err := attack.LoadUpdateMeta(app.matrix.MetaPath)
	if os.IsNotExist(err) {
		return attack.UpdateMeta{}, nil
	}
	if err != nil {
		return attack.UpdateMeta{}, fmt.Errorf("load update metadata: %w", err)
	}
	return meta, nil
}
