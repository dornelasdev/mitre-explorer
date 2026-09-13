package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"mitre-explorer/internal/attack"
)

func TestReadLine(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  string
	}{
		{"newline", "  q  \n", "q"},
		{"blank line", "\n", ""},
		{"final line without newline", "  q  ", "q"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := bufio.NewReader(strings.NewReader(tc.input))
			got, err := readLine(reader)
			if err != nil || got != tc.want {
				t.Fatalf("readLine() = %q, %v; want %q, nil", got, err, tc.want)
			}
			if _, err := readLine(reader); !errors.Is(err, io.EOF) {
				t.Fatalf("next read error = %v; want EOF", err)
			}
		})
	}
}

func TestReadLineErrors(t *testing.T) {
	wantErr := errors.New("input failed")
	reader := bufio.NewReader(iotest.ErrReader(wantErr))
	if _, err := readLine(reader); !errors.Is(err, wantErr) {
		t.Fatalf("read error = %v; want %v", err, wantErr)
	}
	reader = bufio.NewReader(strings.NewReader(""))
	if _, err := readLine(reader); !errors.Is(err, io.EOF) {
		t.Fatalf("empty input error = %v; want EOF", err)
	}
}

func TestInteractiveEOFExits(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mode  string
		input string
	}{
		{"mode menu", "menu", ""},
		{"manual mode", "menu", "2\n"},
		{"pagination", "pagination", ""},
		{"data component list", "components", ""},
		{"data component details", "components", "1\n"},
		{"detection list", "detections", ""},
		{"detection details", "detections", "1\n"},
		{"analytic list", "analytics", ""},
		{"analytic details", "analytics", "1\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Isolate stdin and bound execution so a loop regression cannot hang tests.
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestInteractiveEOFHelper$")
			cmd.Env = append(os.Environ(), "MITRE_EXPLORER_EOF_TEST="+tc.mode)
			cmd.Stdin = strings.NewReader(tc.input)
			cmd.Stdout = io.Discard
			cmd.Stderr = io.Discard
			if err := cmd.Run(); err != nil {
				t.Fatalf("interactive flow failed to exit: %v (context: %v)", err, ctx.Err())
			}
		})
	}
}

func TestInteractiveEOFHelper(t *testing.T) {
	mode := os.Getenv("MITRE_EXPLORER_EOF_TEST")
	if mode == "" {
		return
	}
	reader := bufio.NewReader(os.Stdin)
	cache := attack.CacheData{
		DataComponents:      []attack.DataComponent{{Name: "Process Creation"}},
		DetectionStrategies: []attack.DetectionStrategy{{ID: "DET0001", Name: "Test detection"}},
		Analytics:           []attack.Analytic{{ID: "AN0001", Name: "Test analytic"}},
	}
	switch mode {
	case "menu":
		startInteractiveMode()
	case "pagination":
		printPaginatedTable("Test", []string{"Name"}, [][]string{{"First"}, {"Second"}}, []int{10}, 1)
	case "components":
		runGuidedDataComponents(cache, reader)
	case "detections":
		runGuidedDetections(cache, reader)
	case "analytics":
		runGuidedAnalytics(cache, reader)
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}
}
