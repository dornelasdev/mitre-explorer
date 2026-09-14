package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestMainExitCodes(t *testing.T) {
	for _, tc := range []struct {
		command string
		code    int
	}{{"help", 0}, {"unknown", 2}, {"--matrix unsupported", 2}, {"search needle", 1}} {
		t.Run(tc.command, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMainExitHelper$")
			cmd.Env = append(os.Environ(), "MITRE_EXPLORER_EXIT_TEST="+tc.command)
			cmd.Dir = t.TempDir()
			var output, diagnostics bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &diagnostics
			err := cmd.Run()
			code := 0
			if err != nil {
				exit, ok := err.(*exec.ExitError)
				if !ok {
					t.Fatal(err)
				}
				code = exit.ExitCode()
			}
			if code != tc.code {
				t.Fatalf("exit = %d, want %d; %s", code, tc.code, diagnostics.String())
			}
			if code != 0 && (!strings.Contains(diagnostics.String(), "Error:") || strings.Contains(output.String(), "Error:")) {
				t.Fatalf("diagnostics not on stderr: %s / %s", output.String(), diagnostics.String())
			}
		})
	}
}

func TestMainExitHelper(t *testing.T) {
	command := os.Getenv("MITRE_EXPLORER_EXIT_TEST")
	if command == "" {
		return
	}
	os.Args = append([]string{os.Args[0], "--plain"}, strings.Fields(command)...)
	main()
}
