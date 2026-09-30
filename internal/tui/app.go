// Package tui provides the full-screen terminal interface.
package tui

import tea "charm.land/bubbletea/v2"

// MatrixOption describes one locally cached ATT&CK matrix available to the TUI.
type MatrixOption struct {
	Name        string
	CachePath   string
	TacticOrder []string
}

// Options contains session state supplied by the command-line application.
type Options struct {
	Matrix      string
	CachePath   string
	TacticOrder []string
	Matrices    []MatrixOption
	Version     string
	Plain       bool
}

// Run starts the full-screen terminal interface.
func Run(options Options) error {
	program := tea.NewProgram(newModel(options))
	_, err := program.Run()
	return err
}
