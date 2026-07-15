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
	TacticOrder []string
}

var enterpriseTacticOrder = []string{
	"Reconnaissance",
	"Resource Development",
	"Initial Access",
	"Execution",
	"Persistence",
	"Privilege Escalation",
	"Stealth",
	"Defense Impairment",
	"Credential Access",
	"Discovery",
	"Lateral Movement",
	"Collection",
	"Command and Control",
	"Exfiltration",
	"Impact",
}

var mobileTacticOrder = []string{
	"Initial Access",
	"Execution",
	"Persistence",
	"Privilege Escalation",
	"Defense Evasion",
	"Credential Access",
	"Discovery",
	"Lateral Movement",
	"Collection",
	"Command and Control",
	"Exfiltration",
	"Impact",
}

var icsTacticOrder = []string{
	"Initial Access",
	"Execution",
	"Persistence",
	"Privilege Escalation",
	"Evasion",
	"Discovery",
	"Lateral Movement",
	"Collection",
	"Command and Control",
	"Inhibit Response Function",
	"Impair Process Control",
	"Impact",
}

var enterpriseMatrix = MatrixConfig{
	Name: "enterprise",
	SourceURL: "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
	RawPath: "data/enterprise-attack.json",
	CachePath: "data/mitre-cache.json",
	MetaPath: "data/update-meta.json",
	TacticOrder: enterpriseTacticOrder,
}

var mobileMatrix = MatrixConfig{
	Name: "mobile",
	SourceURL: "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json",
	RawPath: "data/mobile-attack.json",
	CachePath: "data/mobile-cache.json",
	MetaPath: "data/mobile-meta.json",
	TacticOrder: mobileTacticOrder,
}

var icsMatrix = MatrixConfig{
	Name: "ics",
	SourceURL: "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json",
	RawPath: "data/ics-attack.json",
	CachePath: "data/ics-cache.json",
	MetaPath: "data/ics-meta.json",
	TacticOrder: icsTacticOrder,
}

var activeMatrix = enterpriseMatrix

func setActiveMatrix(name string) error {
	matrixName := strings.ToLower(strings.TrimSpace(name))

	switch matrixName {
	case "", "enterprise":
		activeMatrix = enterpriseMatrix
	case "mobile":
		activeMatrix = mobileMatrix
	case "ics":
		activeMatrix = icsMatrix
	default:
		return fmt.Errorf("unsupported matrix %q. Supported matrices: enterprise, mobile, ics", name)
	}

	cachePath = activeMatrix.CachePath
	metaPath = activeMatrix.MetaPath

	return nil
}

func activeMatrixName() string {
	return activeMatrix.Name
}