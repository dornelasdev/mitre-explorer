package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func TestViewAdaptsToTerminalSize(t *testing.T) {
	tests := []struct {
		name      string
		width     int
		height    int
		want      []string
		doNotWant string
	}{
		{
			name:   "wide",
			width:  110,
			height: 30,
			want:   []string{"__  __", "NAVIGATE", "TUI FOUNDATION", "Matrix: enterprise"},
		},
		{
			name:      "compact",
			width:     60,
			height:    16,
			want:      []string{"MITRE EXPLORER", "Responsive compact layout active."},
			doNotWant: "__  __",
		},
		{
			name:   "small",
			width:  30,
			height: 8,
			want:   []string{"Terminal too small", "30x8", "q / Esc / Ctrl+C"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			updated, _ := newModel(Options{Matrix: "enterprise", CachePath: "data/cache.json", Version: "test", Plain: true}).Update(tea.WindowSizeMsg{Width: test.width, Height: test.height})
			view := updated.(model).View()
			if !view.AltScreen || view.WindowTitle != "MITRE Explorer" {
				t.Fatalf("unexpected view settings: alt=%v title=%q", view.AltScreen, view.WindowTitle)
			}
			for _, want := range test.want {
				if !strings.Contains(view.Content, want) {
					t.Fatalf("view missing %q:\n%s", want, view.Content)
				}
			}
			if test.doNotWant != "" && strings.Contains(view.Content, test.doNotWant) {
				t.Fatalf("view unexpectedly contains %q:\n%s", test.doNotWant, view.Content)
			}
		})
	}
}

func TestQuitKeys(t *testing.T) {
	keys := []tea.KeyPressMsg{
		{Code: 'q', Text: "q"},
		{Code: tea.KeyEscape},
		{Code: 'c', Mod: tea.ModCtrl},
	}

	for _, key := range keys {
		_, command := newModel(Options{}).Update(key)
		if command == nil {
			t.Fatalf("key %q did not return a quit command", key.String())
		}
		if _, ok := command().(tea.QuitMsg); !ok {
			t.Fatalf("key %q returned a non-quit command", key.String())
		}
	}
}
