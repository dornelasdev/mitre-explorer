package main

import (
	"os"

	"mitre-explorer/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], version))
}
