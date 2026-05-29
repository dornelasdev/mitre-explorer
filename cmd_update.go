package main

import (
	"fmt"
	"os"
)

func handleUpdate(args []string) {
	const sourceURL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
	const rawPath = "data/enterprise-attack.json"

	force := len(args) >= 2 && (args[1] == "-f" || args[1] == "--force")
	if len(args) > 2 {
		fmt.Println("Usage: go run . update [-f|--force] [--plain]")
		return
	}
	if len(args) == 2 && args[1] != "-f" && args[1] != "--force" {
		fmt.Println("Usage: go run . update [-f|--force] [--plain]")
		return
	}

	meta, err := loadUpdateMeta(metaPath)
	if err != nil && !os.IsNotExist(err) {
		fmt.Printf("Failed to read update metadata: %v\n", err)
		return
	}

	stop := startSpinner("Checking/downloading ATT&CK data")
	dl, err := downloadFileConditional(sourceURL, rawPath, meta, force)
	stop()
	if err != nil {
		fmt.Printf("Update failed: %v\n", err)
		return
	}

	if dl.NotModified {
		fmt.Println(warn("Remote dataset unchanged (304 Not Modified)."))
		if _, err := os.Stat(cachePath); err == nil {
			fmt.Println("Local cache is already up to date.")
			return
		}

		fmt.Println(warn("Cache file missing. Rebuilding cache from local raw dataset."))
	}

	if _, err := os.Stat(rawPath); err != nil {
		if os.IsNotExist(err) {
			fmt.Println("Raw dataset file is missing. Run: go run . update -f")
			return
		}
		fmt.Printf("Error checking raw dataset file: %v\n", err)
		return
	}

	if !dl.Downloaded {
		info, err := os.Stat(rawPath)
		if err != nil {
			fmt.Printf("Error reading raw dataset size: %v\n", err)
			return
		}
		dl.Bytes = info.Size()
	}

	cache, err := buildCacheDataFromSTIX(rawPath)
	if err != nil {
		fmt.Printf("Parse failed: %v\n", err)
		return
	}

	if err := saveCacheData(cachePath, cache); err != nil {
		fmt.Printf("Cache write failed: %v\n", err)
		return
	}

	if err := saveUpdateMeta(metaPath, UpdateMeta{
		ETag:         dl.ETag,
		LastModified: dl.LastModified,
	}); err != nil {
		fmt.Printf("Warning: failed to save update metadata: %v\n", err)
	}

	fmt.Println(ok("Update complete."))
	fmt.Printf("Source: %s\n", sourceURL)
	fmt.Printf("Saved: %s\n", rawPath)
	fmt.Printf("Size: %s (%d bytes)\n", humanSize(dl.Bytes), dl.Bytes)
	fmt.Printf("Cache: %s\n", cachePath)
	fmt.Printf("Parsed techniques: %d\n", len(cache.Techniques))
	fmt.Printf("Parsed groups: %d\n", len(cache.Groups))
	fmt.Printf("Parsed mitigations: %d\n", len(cache.Mitigations))
	fmt.Printf("Parsed campaigns: %d\n", len(cache.Campaigns))
	fmt.Printf("Parsed relationships: %d\n", len(cache.Relationships))
	fmt.Printf("Parsed data components: %d\n", len(cache.DataComponents))

	if dl.Downloaded {
		fmt.Println("Download status: downloaded new dataset")
	} else {
		fmt.Println("Download status: reused local raw dataset")
	}
}
