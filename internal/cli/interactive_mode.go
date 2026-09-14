package cli

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"unicode"
)

func (app *App) startInteractiveMode() {
	reader := app.reader
	for {
		fmt.Fprintf(app.out, "Matrix: %s\n", app.activeMatrixName())
		fmt.Fprintln(app.out, "  [1] Guided Explorer")
		fmt.Fprintln(app.out, "  [2] Manual Command Mode")
		fmt.Fprintln(app.out, "  [q] Quit")
		fmt.Fprint(app.out, "> ")

		choice, err := readLine(reader)
		if err != nil {
			return
		}

		switch strings.ToLower(choice) {
		case "1":
			fmt.Fprintln(app.out, "Guided Explorer mode selected.")
			app.runGuidedExplorer()

		case "2":
			fmt.Fprintln(app.out, "Manual mode selected.")
			fmt.Fprintln(app.out, "Type a command (without `go run .`), for example:")
			fmt.Fprintln(app.out, "  search powershell --limit 5 --detailed")
			fmt.Fprintln(app.out, "  show T1059")
			fmt.Fprintln(app.out, "  list techniques --tactic execution --plain")
			fmt.Fprintln(app.out, "Type `back` to return to mode menu, or `q` to quit.")

			for {
				fmt.Fprint(app.out, "manual> ")
				line, err := readLine(reader)
				if err != nil {
					return
				}
				if line == "" {
					continue
				}
				if strings.EqualFold(line, "back") {
					break
				}
				if strings.EqualFold(line, "q") {
					fmt.Fprintln(app.out, "Exiting.")
					return
				}

				cmdArgs, err := parseCommandLine(line)
				if err != nil {
					app.reportError(invalidUsage("manual command: %v", err))
					continue
				}
				app.runCommand(cmdArgs)
			}
		case "q":
			fmt.Fprintln(app.out, "Exiting.")
			return

		default:
			fmt.Fprintln(app.out, "Invalid choice.")
		}
	}
}

// parseCommandLine handles whitespace, quotes, and backslash escapes in manual mode.
// The user's shell performs this parsing for standalone commands.
func parseCommandLine(line string) ([]string, error) {
	var args []string
	var token strings.Builder
	var quote rune
	escaped := false
	started := false

	flush := func() {
		if started {
			args = append(args, token.String())
			token.Reset()
			started = false
		}
	}

	for _, r := range line {
		if escaped {
			token.WriteRune(r)
			escaped = false
			started = true
			continue
		}
		if r == '\\' && quote != '\'' {
			escaped = true
			started = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				token.WriteRune(r)
			}
			started = true
			continue
		}
		switch {
		case r == '\'' || r == '"':
			quote = r
			started = true
		case unicode.IsSpace(r):
			flush()
		default:
			token.WriteRune(r)
			started = true
		}
	}
	if escaped {
		return nil, fmt.Errorf("unfinished escape")
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote")
	}
	flush()
	return args, nil
}

func readLine(reader *bufio.Reader) (string, error) {
	input, err := reader.ReadString('\n')
	// Process a final unterminated line before reporting EOF on the next read.
	if err == io.EOF && len(input) > 0 {
		err = nil
	}
	return strings.TrimSpace(input), err
}
