// Package cli handles terminal commands and interactive ATT&CK exploration.
package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// App owns the state and streams for one sequential terminal session.
type App struct {
	reader   *bufio.Reader
	out      io.Writer
	errOut   io.Writer
	matrix   MatrixConfig
	useColor bool
}

// New creates an Enterprise session with its own input buffer and color settings.
// Nil input means EOF; nil output discards terminal messages.
func New(input io.Reader, output io.Writer) *App {
	return NewWithStreams(input, output, output)
}

// NewWithStreams separates command results from failure diagnostics.
func NewWithStreams(input io.Reader, output, diagnostics io.Writer) *App {
	if input == nil {
		input = strings.NewReader("")
	}
	if output == nil {
		output = io.Discard
	}
	if diagnostics == nil {
		diagnostics = io.Discard
	}
	matrix, _ := matrixFor("enterprise")
	return &App{
		reader:   bufio.NewReader(input),
		out:      output,
		errOut:   diagnostics,
		matrix:   matrix,
		useColor: true,
	}
}

// Run starts a fresh session on the process streams and returns its exit code.
func Run(args []string, version string) int {
	return NewWithStreams(os.Stdin, os.Stdout, os.Stderr).Run(args, version)
}

// Run returns 0 on success, 1 on command failure, or 2 on invalid usage.
func (app *App) Run(args []string, version string) int {
	fmt.Fprintf(app.out, "MITRE Explorer %s\n", version)

	filtered, err := app.applyGlobalOptions(args)
	if err != nil {
		return app.reportError(err, args...)
	}
	args = filtered

	if len(args) == 0 {
		app.startInteractiveMode()
		return 0
	}

	return app.reportError(app.dispatchCommand(args))
}
