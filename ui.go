package main

import (
	"fmt"
	"strings"
	"time"
)

func startSpinner(message string) func() {
	done := make(chan struct{})

	go func() {
		frames := []rune{'|', '/', '-', '\\'}
		i := 0
		for {
			select {
			case <-done:
				fmt.Printf("\r%s... done\n", message)

				return
			default:
				fmt.Printf("\r%s... %c", message, frames[i%len(frames)])
				time.Sleep(120 * time.Millisecond)
				i++
			}
		}
	}()

	return func() { close(done) }
}

func humanSize(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cCyan   = "\033[36m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cRed    = "\033[31m"
)

var useColor = true

func title(text string) string {
	if !useColor {
		return text
	}
	return cBold + cCyan + text + cReset
}

func ok(text string) string {
	if !useColor {
		return text
	}
	return cGreen + text + cReset
}

func warn(text string) string {
	if !useColor {
		return text
	}
	return cYellow + text + cReset
}

func errText(text string) string {
	if !useColor {
		return text
	}
	return cRed + text + cReset
}

func label(text string) string {
	if !useColor {
		return text
	}
	return cBold + text + cReset
}

func printTechniqueTable(techniques []Technique) {
	const nameWidth = 72

	fmt.Printf("%-4s %-12s %s\n", "#", "ID", "Name")
	fmt.Println(strings.Repeat("-", 4+1+12+1+nameWidth))
	for i, t := range techniques {
		name := truncateText(t.Name, nameWidth)
		fmt.Printf("%-4d %-12s %s\n", i+1, t.ID, name)
	}
}

func truncateText(s string, max int) string {
	if max <= 0 {
		return s
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max <= 1 {
		return "..."
	}
	return string(r[:max-1]) + "..."
}
