package tui

import (
	"strings"

	tea "charm.land/bubbletea/v2"
)

type matrixPickerState struct {
	active bool
	cursor int
}

func (m model) currentMatrix() MatrixOption {
	return MatrixOption{
		Name:        m.options.Matrix,
		CachePath:   m.options.CachePath,
		TacticOrder: append([]string(nil), m.options.TacticOrder...),
	}
}

func (m model) availableMatrices() []MatrixOption {
	if len(m.options.Matrices) == 0 {
		return []MatrixOption{m.currentMatrix()}
	}
	matrices := make([]MatrixOption, len(m.options.Matrices))
	for index, matrix := range m.options.Matrices {
		matrices[index] = MatrixOption{
			Name:        matrix.Name,
			CachePath:   matrix.CachePath,
			TacticOrder: append([]string(nil), matrix.TacticOrder...),
		}
	}
	return matrices
}

func (m *model) startMatrixPicker() {
	m.matrixPicker.active = true
	m.matrixPicker.cursor = 0
	for index, matrix := range m.availableMatrices() {
		if strings.EqualFold(matrix.Name, m.options.Matrix) {
			m.matrixPicker.cursor = index
			break
		}
	}
}

func (m model) updateMatrixPicker(key string) (tea.Model, tea.Cmd) {
	matrices := m.availableMatrices()
	switch key {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "esc", "b", "m":
		m.matrixPicker.active = false
		return m, nil
	case "up", "k":
		m.matrixPicker.cursor = max(0, m.matrixPicker.cursor-1)
	case "down", "j":
		m.matrixPicker.cursor = min(len(matrices)-1, m.matrixPicker.cursor+1)
	case "enter":
		if len(matrices) == 0 {
			return m, nil
		}
		selected := matrices[m.matrixPicker.cursor]
		m.matrixPicker.active = false
		if strings.EqualFold(selected.Name, m.options.Matrix) && m.loadErr == nil {
			return m, nil
		}
		m.loading = true
		m.loadErr = nil
		m.failedMatrix = nil
		loading := selected
		m.loadingMatrix = &loading
		return m, loadCache(selected)
	}
	return m, nil
}
