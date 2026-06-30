package main

import (
	"fmt"
	"os"
)

func handleStatus(args []string) {
	_ = args
	cacheInfo, cacheErr := os.Stat(cachePath)
	metaInfo, metaErr := os.Stat(metaPath)

	fmt.Println(title("MITRE Explorer Status"))

	if cacheErr != nil {
		if os.IsNotExist(cacheErr) {
			fmt.Println(errText("Cache: missing"))
			fmt.Println("Run: go run . update")
			return
		}
		fmt.Printf("Error checking cache file: %v\n", cacheErr)
		return
	}

	fmt.Printf("%s %s\n", label("Cache:"), ok("present"))
	fmt.Printf("%s %s\n", label("Cache file:"), cachePath)
	fmt.Printf("%s %s\n", label("Cache size:"), humanSize(cacheInfo.Size()))
	fmt.Printf("%s %s\n", label("Cache modified:"), cacheInfo.ModTime().Format("2006-01-02 15:04:05"))

	if metaErr == nil {
		fmt.Printf("%s %s\n", label("Update metadata:"), ok("present"))
		fmt.Printf("%s %s\n", label("Metadata file:"), metaPath)
		fmt.Printf("%s %s\n", label("Metadata modified:"), metaInfo.ModTime().Format("2006-01-02 15:04:05"))

		meta, err := loadUpdateMeta(metaPath)
		if err == nil {
			fmt.Printf("%s %s\n", label("ETag:"), emptyFallback(meta.ETag))
			fmt.Printf("%s %s\n", label("Last modified:"), emptyFallback(meta.LastModified))
		}
	} else if os.IsNotExist(metaErr) {
		fmt.Println(warn("Update metadata: missing"))
	} else {
		fmt.Printf("Update metadata: error reading metadata file: %v\n", metaErr)
	}

	cache, err := loadCacheData(cachePath)
	if err != nil {
		fmt.Printf("Error loading cache: %v\n", err)
		return
	}

	fmt.Println()
	fmt.Println(title("Cache Contents"))
	fmt.Printf("%s %d\n", label("Techniques:"), len(cache.Techniques))
	fmt.Printf("%s %d\n", label("Groups:"), len(cache.Groups))
	fmt.Printf("%s %d\n", label("Mitigations:"), len(cache.Mitigations))
	fmt.Printf("%s %d\n", label("Software:"), len(cache.Softwares))
	fmt.Printf("%s %d\n", label("Campaigns:"), len(cache.Campaigns))
	fmt.Printf("%s %d\n", label("Detection Strategies:"), len(cache.DetectionStrategies))
	fmt.Printf("%s %d\n", label("Analytics:"), len(cache.Analytics))
	fmt.Printf("%s %d\n", label("Data Components:"), len(cache.DataComponents))
	fmt.Printf("%s %d\n", label("Relationships:"), len(cache.Relationships))
}

func emptyFallback(value string) string {
	if value == "" {
		return "Not available"
	}
	return value
}