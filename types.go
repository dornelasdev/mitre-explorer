package main

type Technique struct {
	ID string `json:"id"`
	Name string `json:"name"`
	Description string `json:"description"`
	Tactics []string `json:"tactics"`
	Platforms []string `json:"platforms"`
	DataSources []string `json:"data_sources"`
	DetectionNotes string `json:"detection_notes"`
}

type STIXBundle struct {
	Objects []STIXObject `json:"objects"`
}

type STIXObject struct {
	Type string `json:"type"`
	Name string `json:"name"`
	Description string `json:"description"`

	KillChainPhases []struct {
		PhaseName string `json:"phase_name"`
	} `json:"kill_chain_phases"`

	XMitrePlatforms []string `json:"x_mitre_platforms"`
	XMitreDataSources []string `json:"x_mitre_data_sources"`
	XMitreDetection string `json:"x_mitre_detection"`

	ExternalReferences []struct {
		SourceName string `json:"source_name"`
		ExternalID string `json:"external_id"`
	} `json:"external_references"`
}

const cachePath = "data/mitre-cache.json"
