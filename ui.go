package main

import (
	"fmt"
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
