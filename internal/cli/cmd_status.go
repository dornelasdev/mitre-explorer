package cli

import (
	"fmt"
	"os"
	"strings"

	"mitre-explorer/internal/attack"
)

func (app *App) handleStatus(args []string) error {
	if len(args) != 1 {
		return invalidUsage("status does not accept arguments")
	}
	cacheInfo, cacheErr := os.Stat(app.matrix.CachePath)
	metaInfo, metaErr := os.Stat(app.matrix.MetaPath)

	fmt.Fprintln(app.out, app.title("MITRE Explorer Status"))
	fmt.Fprintf(app.out, "%s %s\n", app.label("Matrix:"), app.activeMatrixName())

	if cacheErr != nil {
		if os.IsNotExist(cacheErr) {
			fmt.Fprintln(app.out, app.errText("Cache: missing"))
			fmt.Fprintf(app.out, "Run: go run . update --matrix %s\n", app.activeMatrixName())
			return nil
		}
		return fmt.Errorf("check cache file: %w", cacheErr)
	}

	fmt.Fprintf(app.out, "%s %s\n", app.label("Cache:"), app.ok("present"))
	fmt.Fprintf(app.out, "%s %s\n", app.label("Cache file:"), app.matrix.CachePath)
	fmt.Fprintf(app.out, "%s %s\n", app.label("Cache size:"), humanSize(cacheInfo.Size()))
	fmt.Fprintf(app.out, "%s %s\n", app.label("Cache modified:"), cacheInfo.ModTime().Format("2006-01-02 15:04:05"))

	if metaErr == nil {
		fmt.Fprintf(app.out, "%s %s\n", app.label("Update metadata:"), app.ok("present"))
		fmt.Fprintf(app.out, "%s %s\n", app.label("Metadata file:"), app.matrix.MetaPath)
		fmt.Fprintf(app.out, "%s %s\n", app.label("Metadata modified:"), metaInfo.ModTime().Format("2006-01-02 15:04:05"))

		meta, err := attack.LoadUpdateMeta(app.matrix.MetaPath)
		if err != nil {
			return fmt.Errorf("load update metadata: %w", err)
		}
		fmt.Fprintf(app.out, "%s %s\n", app.label("ETag:"), emptyFallback(meta.ETag))
		fmt.Fprintf(app.out, "%s %s\n", app.label("Last modified:"), emptyFallback(meta.LastModified))
	} else if os.IsNotExist(metaErr) {
		fmt.Fprintln(app.out, app.warn("Update metadata: missing"))
	} else {
		return fmt.Errorf("check update metadata: %w", metaErr)
	}

	cache, err := attack.LoadCacheData(app.matrix.CachePath)
	if err != nil {
		return fmt.Errorf("load cache: %w", err)
	}

	fmt.Fprintln(app.out)
	fmt.Fprintln(app.out, app.title("Cache Contents"))
	fmt.Fprintf(app.out, "%s %d\n", app.label("Techniques:"), len(cache.Techniques))
	fmt.Fprintf(app.out, "%s %d\n", app.label("Groups:"), len(cache.Groups))
	fmt.Fprintf(app.out, "%s %d\n", app.label("Mitigations:"), len(cache.Mitigations))
	fmt.Fprintf(app.out, "%s %d\n", app.label("Software:"), len(cache.Softwares))
	fmt.Fprintf(app.out, "%s %d\n", app.label("Campaigns:"), len(cache.Campaigns))
	fmt.Fprintf(app.out, "%s %d\n", app.label("Detection Strategies:"), len(cache.DetectionStrategies))
	fmt.Fprintf(app.out, "%s %d\n", app.label("Analytics:"), len(cache.Analytics))
	fmt.Fprintf(app.out, "%s %d\n", app.label("Data Components:"), len(cache.DataComponents))
	fmt.Fprintf(app.out, "%s %d\n", app.label("Relationships:"), len(cache.Relationships))
	app.printMatrixTacticStatus(cache)
	return nil
}

func (app *App) printMatrixTacticStatus(cache attack.CacheData) {
	known, unknown := attack.ValidateTactics(cache.Techniques, app.matrix.TacticOrder)

	fmt.Fprintln(app.out)
	fmt.Fprintln(app.out, app.title("Matrix Tactics"))
	fmt.Fprintf(app.out, "%s %d\n", app.label("Known tactics:"), len(known))
	fmt.Fprintf(app.out, "%s %d\n", app.label("Unknown tactics:"), len(unknown))

	if len(unknown) > 0 {
		fmt.Fprintf(app.out, "%s %s\n", app.label("Unknown tactic names:"), strings.Join(unknown, ", "))
	}
}

func emptyFallback(value string) string {
	if value == "" {
		return "Not available"
	}
	return value
}
