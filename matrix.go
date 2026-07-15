package main

import (
	"fmt"
	"strings"
)

type MatrixConfig struct {
	Name string
	SourceURL string
	RawPath string
	CachePath string
	MetaPath string
}

var enterpriseMatrix = MatrixConfig{
	Name: "enterprise",
	SourceURL: "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
	RawPath: "data/enterprise-attack.json",
	CachePath: "data/mitre-cache.json",
	MetaPath: "data/update-meta.json",
}

var mobileMatrix = MatrixConfig{
	Name: "mobile",
	SourceURL: "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json",
	RawPath: "data/mobile-attack.json",
	CachePath: "data/mobile-cache.json",
	MetaPath: "data/mobile-meta.json",
}


var activeMatrix = enterpriseMatrix

func setActiveMatrix(name string) error {
	matrixName := strings.ToLower(strings.TrimSpace(name))

	switch matrixName {
	case "", "enterprise":
		activeMatrix = enterpriseMatrix
	case "mobile":
		activeMatrix = mobileMatrix
	default:
		return fmt.Errorf("unsupported matrix %q. Supported matrices: enterprise, mobile", name)
	}

	cachePath = activeMatrix.CachePath
	metaPath = activeMatrix.MetaPath

	return nil
}

func activeMatrixName() string {
	return activeMatrix.Name
}