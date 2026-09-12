package main

import (
	"fmt"
)

func runApp(args []string) {
	fmt.Printf("MITRE Explorer %s\n", version)

	args, ok := applyGlobalOptions(args)
	if !ok {
		return
	}

	if len(args) == 0 {
		startInteractiveMode()
		return
	}

	dispatchCommand(args)
}
