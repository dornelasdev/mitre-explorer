package cli

import (
	"fmt"
	"os"

	"mitre-explorer/internal/attack"
)

func (app *App) handleUpdate(args []string) error {
	sourceURL := app.matrix.SourceURL
	rawPath := app.matrix.RawPath

	force := len(args) >= 2 && (args[1] == "-f" || args[1] == "--force")
	rebuild := len(args) == 2 && args[1] == "--rebuild"
	if len(args) > 2 {
		return invalidUsage("update accepts either -f/--force or --rebuild")
	}
	if len(args) == 2 && !force && !rebuild {
		return invalidUsage("update accepts either -f/--force or --rebuild")
	}
	if rebuild {
		cache, err := app.buildAndSaveCache()
		if err != nil {
			return err
		}
		fmt.Fprintln(app.out, app.ok("Cache rebuilt from local dataset."))
		fmt.Fprintf(app.out, "Matrix: %s\nRaw dataset: %s\nCache: %s\n", app.activeMatrixName(), rawPath, app.matrix.CachePath)
		app.printParsedCounts(cache)
		fmt.Fprintln(app.out, "No download performed; update metadata unchanged.")
		return nil
	}

	meta, err := app.loadUpdateMetaForCommand()
	if err != nil {
		return err
	}

	stop := app.startSpinner("Checking/downloading ATT&CK data")
	dl, err := attack.DownloadFileConditional(sourceURL, rawPath, meta, force)
	stop()
	if err != nil {
		return fmt.Errorf("update failed: %w", err)
	}

	if dl.NotModified {
		fmt.Fprintln(app.out, app.warn("Remote dataset unchanged (304 Not Modified)."))
		if _, err := attack.LoadCacheData(app.matrix.CachePath); err == nil {
			fmt.Fprintln(app.out, "Local cache is already up to date.")
			return nil
		} else if os.IsNotExist(err) {
			fmt.Fprintln(app.out, app.warn("Cache file missing. Rebuilding cache from local raw dataset."))
		} else {
			fmt.Fprintln(app.out, app.warn("Cache file is unreadable or invalid. Rebuilding cache from local raw dataset."))
		}
	}

	if _, err := os.Stat(rawPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("raw dataset missing; run: go run . update -f --matrix %s", app.activeMatrixName())
		}
		return fmt.Errorf("check raw dataset file: %w", err)
	}

	if !dl.Downloaded {
		info, err := os.Stat(rawPath)
		if err != nil {
			return fmt.Errorf("read raw dataset size: %w", err)
		}
		dl.Bytes = info.Size()
	}

	cache, err := app.buildAndSaveCache()
	if err != nil {
		return err
	}

	if err := attack.SaveUpdateMeta(app.matrix.MetaPath, attack.UpdateMeta{
		ETag:         dl.ETag,
		LastModified: dl.LastModified,
	}); err != nil {
		return fmt.Errorf("cache updated, but saving update metadata failed: %w", err)
	}

	fmt.Fprintln(app.out, app.ok("Update complete."))
	fmt.Fprintf(app.out, "Matrix: %s\n", app.activeMatrixName())
	fmt.Fprintf(app.out, "Source: %s\n", sourceURL)
	fmt.Fprintf(app.out, "Saved: %s\n", rawPath)
	fmt.Fprintf(app.out, "Size: %s (%d bytes)\n", humanSize(dl.Bytes), dl.Bytes)
	fmt.Fprintf(app.out, "Cache: %s\n", app.matrix.CachePath)
	app.printParsedCounts(cache)

	if dl.Downloaded {
		fmt.Fprintln(app.out, "Download status: downloaded new dataset")
	} else {
		fmt.Fprintln(app.out, "Download status: reused local raw dataset")
	}
	return nil
}

func (app *App) buildAndSaveCache() (attack.CacheData, error) {
	cache, err := attack.BuildCacheDataFromSTIX(app.matrix.RawPath)
	if err != nil {
		if os.IsNotExist(err) {
			return attack.CacheData{}, fmt.Errorf("raw dataset missing; run: go run . update --matrix %s", app.activeMatrixName())
		}
		return attack.CacheData{}, fmt.Errorf("parse dataset: %w", err)
	}
	if err := attack.SaveCacheData(app.matrix.CachePath, cache); err != nil {
		return attack.CacheData{}, fmt.Errorf("write cache: %w", err)
	}
	return cache, nil
}

func (app *App) printParsedCounts(cache attack.CacheData) {
	fmt.Fprintf(app.out, "Parsed techniques: %d\n", len(cache.Techniques))
	fmt.Fprintf(app.out, "Parsed groups: %d\n", len(cache.Groups))
	fmt.Fprintf(app.out, "Parsed mitigations: %d\n", len(cache.Mitigations))
	fmt.Fprintf(app.out, "Parsed campaigns: %d\n", len(cache.Campaigns))
	fmt.Fprintf(app.out, "Parsed relationships: %d\n", len(cache.Relationships))
	fmt.Fprintf(app.out, "Parsed data components: %d\n", len(cache.DataComponents))
	fmt.Fprintf(app.out, "Parsed detection strategies: %d\n", len(cache.DetectionStrategies))
}
