package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

type DownloadResult struct {
	Downloaded   bool
	NotModified  bool
	Bytes        int64
	ETag         string
	LastModified string
}

func downloadFileConditional(url, outputPath string, prev UpdateMeta, force bool) (DownloadResult, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return DownloadResult{}, err
	}

	if !force {
		if prev.ETag != "" {
			req.Header.Set("If-None-Match", prev.ETag)
		}
		if prev.LastModified != "" {
			req.Header.Set("If-Modified-Since", prev.LastModified)
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return DownloadResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return DownloadResult{
			NotModified:  true,
			ETag:         prev.ETag,
			LastModified: prev.LastModified,
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return DownloadResult{}, fmt.Errorf("Unexpected HTTP status: %s", resp.Status)
	}

	if err := os.MkdirAll("data", 0o755); err != nil {
		return DownloadResult{}, err
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return DownloadResult{}, err
	}
	defer file.Close()

	n, err := io.Copy(file, resp.Body)
	if err != nil {
		return DownloadResult{}, err
	}

	etag := resp.Header.Get("ETag")
	if etag == "" {
		etag = prev.ETag
	}

	lastMod := resp.Header.Get("Last-Modified")
	if lastMod == "" {
		lastMod = prev.LastModified
	}

	return DownloadResult{
		Downloaded:   true,
		Bytes:        n,
		ETag:         etag,
		LastModified: lastMod,
	}, nil
}

func buildTechniquesFromSTIX(path string) ([]Technique, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var bundle STIXBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, err
	}

	var techniques []Technique

	for _, obj := range bundle.Objects {
		if obj.Type != "attack-pattern" {
			continue
		}

		id := ""
		for _, ref := range obj.ExternalReferences {
			if ref.SourceName == "mitre-attack" && ref.ExternalID != "" {
				id = ref.ExternalID
				break
			}
		}
		if id == "" {
			continue
		}

		var tactics []string
		for _, phase := range obj.KillChainPhases {
			if phase.PhaseName != "" {
				tactics = append(tactics, phase.PhaseName)
			}
		}

		techniques = append(techniques, Technique{
			ID:             id,
			Name:           obj.Name,
			Description:    obj.Description,
			Tactics:        tactics,
			Platforms:      obj.XMitrePlatforms,
			DataSources:    obj.XMitreDataSources,
			DetectionNotes: obj.XMitreDetection,
			DataComponents: obj.XMitreDataComponents,
		})
	}

	return techniques, nil
}

func saveTechniques(path string, techniques []Technique) error {
	data, err := json.MarshalIndent(techniques, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll("data", 0o755); err != nil {
		return err
	}

	return os.WriteFile(path, data, 0o644)
}

func loadTechniques(path string) ([]Technique, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var techniques []Technique
	if err := json.Unmarshal(data, &techniques); err != nil {
		return nil, err
	}

	return techniques, nil
}

func loadUpdateMeta(path string) (UpdateMeta, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return UpdateMeta{}, err
	}

	var m UpdateMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return UpdateMeta{}, err
	}
	return m, nil
}

func saveUpdateMeta(path string, m UpdateMeta) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll("data", 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func buildCacheDataFromSTIX(path string) (CacheData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return CacheData{}, err
	}

	var bundle STIXBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return CacheData{}, err
	}

	stixToExternal := make(map[string]string, len(bundle.Objects))
	stixToType := make(map[string]string, len(bundle.Objects))

	for _, obj := range bundle.Objects {
		extID := extractExternalID(obj.ExternalReferences)
		if extID != "" {
			stixToExternal[obj.ID] = extID
		}

		if obj.XMitreDeprecated || obj.Revoked {
			continue
		}

		switch obj.Type {
		case "attack-pattern":
			stixToType[obj.ID] = "technique"
		case "intrusion-set":
			stixToType[obj.ID] = "group"
		case "course-of-action":
			stixToType[obj.ID] = "mitigation"
		case "malware", "tool":
			stixToType[obj.ID] = "software"
		case "campaign":
			stixToType[obj.ID] = "campaign"
		case "x-mitre-data-component":
			stixToType[obj.ID] = "data_component"
		case "x-mitre-detection-strategy":
			stixToType[obj.ID] = "detection_strategy"
		case "x-mitre-analytic":
			stixToType[obj.ID] = "analytic"
		}

	}
	techniques := make([]Technique, 0)
	groups := make([]Group, 0)
	mitigations := make([]Mitigation, 0)
	relationships := make([]Relationship, 0)
	softwares := make([]Software, 0)
	campaigns := make([]Campaign, 0)
	dataComponents := make([]DataComponent, 0)
	dsToComponentRefs := make(map[string][]string)
	analyticToComponentRefs := make(map[string][]string)
	dsToAnalyticRefs := make(map[string][]string)
	dsDetectionText := make(map[string][]string)
	analyticDetectionText := make(map[string][]string)
	techDetectionText := make(map[string][]string)
	detectionStrategies := make([]DetectionStrategy, 0)
	analytics := make([]Analytic, 0)

	for _, obj := range bundle.Objects {
		if obj.XMitreDeprecated || obj.Revoked {
			continue
		}
		if obj.Type != "x-mitre-analytic" {
			continue
		}

		for _, ls := range obj.XMitreLogSourceReferences {
			ref := strings.TrimSpace(ls.XMitreDataComponentRef)
			if ref == "" || !strings.HasPrefix(ref, "x-mitre-data-component--") {
				continue
			}
			analyticToComponentRefs[obj.ID] = append(analyticToComponentRefs[obj.ID], ref)
		}
		analyticDetectionText[obj.ID] = appendUniqueText(analyticDetectionText[obj.ID], obj.Name)
		analyticDetectionText[obj.ID] = appendUniqueText(analyticDetectionText[obj.ID], obj.Description)
	}

	for _, obj := range bundle.Objects {
		if obj.XMitreDeprecated || obj.Revoked {
			continue
		}
		if obj.Type != "x-mitre-detection-strategy" {
			continue
		}

		dsDetectionText[obj.ID] = appendUniqueText(dsDetectionText[obj.ID], obj.Name)
		dsDetectionText[obj.ID] = appendUniqueText(dsDetectionText[obj.ID], obj.Description)

		for _, ref := range obj.XMitreAnalyticRefs {
			if strings.HasPrefix(ref, "x-mitre-analytic--") {
				dsToAnalyticRefs[obj.ID] = append(dsToAnalyticRefs[obj.ID], ref)
			}
		}

		for _, ref := range obj.ObjectRefs {
			if strings.HasPrefix(ref, "x-mitre-data-component--") {
				dsToComponentRefs[obj.ID] = append(dsToComponentRefs[obj.ID], ref)
			}
		}

		for _, analyticRef := range dsToAnalyticRefs[obj.ID] {
			for _, dcRef := range analyticToComponentRefs[analyticRef] {
				dsToComponentRefs[obj.ID] = append(dsToComponentRefs[obj.ID], dcRef)
			}
		}
	}

	for _, obj := range bundle.Objects {
		if obj.XMitreDeprecated || obj.Revoked {
			continue
		}

		switch obj.Type {
		case "attack-pattern":
			tid := stixToExternal[obj.ID]
			if tid == "" || !hasIDPrefix(tid, "T") {
				continue
			}

			var tactics []string
			for _, p := range obj.KillChainPhases {
				if p.PhaseName != "" {
					tactics = append(tactics, p.PhaseName)
				}
			}

			techniques = append(techniques, Technique{
				ID:             tid,
				Name:           obj.Name,
				Description:    obj.Description,
				Tactics:        tactics,
				Platforms:      obj.XMitrePlatforms,
				DataSources:    obj.XMitreDataSources,
				DetectionNotes: obj.XMitreDetection,
				DataComponents: obj.XMitreDataComponents,
			})

			for _, ref := range obj.ObjectRefs {
				if !strings.HasPrefix(ref, "x-mitre-data-component--") {
					continue
				}

				targetID := stixToExternal[ref]
				if targetID == "" {
					targetID = ref
				}

				relationships = append(relationships, Relationship{
					Type:       "has_data_component",
					SourceType: "technique",
					SourceID:   tid,
					TargetType: "data_component",
					TargetID:   targetID,
				})
			}

		case "intrusion-set":
			gid := stixToExternal[obj.ID]
			if gid == "" || !hasIDPrefix(gid, "G") {
				continue
			}
			groups = append(groups, Group{
				ID:          gid,
				Name:        obj.Name,
				Description: obj.Description,
				Aliases:     obj.XMitreAliases,
			})

		case "course-of-action":
			mid := stixToExternal[obj.ID]
			if mid == "" || !hasIDPrefix(mid, "M") {
				continue
			}

			mitigations = append(mitigations, Mitigation{
				ID:          mid,
				Name:        obj.Name,
				Description: obj.Description,
			})
		case "relationship":
			sourceID := stixToExternal[obj.SourceRef]
			targetID := stixToExternal[obj.TargetRef]
			sourceType := stixToType[obj.SourceRef]
			targetType := stixToType[obj.TargetRef]

			if sourceType == "detection_strategy" && sourceID == "" {
				sourceID = obj.SourceRef
			}

			if targetID == "" || sourceType == "" || targetType == "" {
				continue
			}

			switch sourceType {
			case "technique":
				if !hasIDPrefix(sourceID, "T") {
					continue
				}
			case "group":
				if !hasIDPrefix(sourceID, "G") {
					continue
				}
			case "mitigation":
				if !hasIDPrefix(sourceID, "M") {
					continue
				}
			case "software":
				if !hasIDPrefix(sourceID, "S") {
					continue
				}
			case "campaign":
				if !hasIDPrefix(sourceID, "C") {
					continue
				}
			case "data_component":

			case "detection_strategy":

			}

			switch targetType {
			case "technique":
				if !hasIDPrefix(targetID, "T") {
					continue
				}
			case "group":
				if !hasIDPrefix(targetID, "G") {
					continue
				}
			case "mitigation":
				if !hasIDPrefix(targetID, "M") {
					continue
				}
			case "software":
				if !hasIDPrefix(targetID, "S") {
					continue
				}
			case "campaign":
				if !hasIDPrefix(targetID, "C") {
					continue
				}
			case "data_component":

			}

			relationships = append(relationships, Relationship{
				Type:       obj.RelationshipType,
				SourceType: sourceType,
				SourceID:   sourceID,
				TargetType: targetType,
				TargetID:   targetID,
			})
		case "malware", "tool":
			sid := stixToExternal[obj.ID]
			if sid == "" || !hasIDPrefix(sid, "S") {
				continue
			}

			softwares = append(softwares, Software{
				ID:          sid,
				Name:        obj.Name,
				Type:        obj.Type,
				Description: obj.Description,
				Aliases:     obj.XMitreAliases,
			})
		case "campaign":
			cid := stixToExternal[obj.ID]
			if cid == "" || !hasIDPrefix(cid, "C") {
				continue
			}

			campaigns = append(campaigns, Campaign{
				ID:          cid,
				Name:        obj.Name,
				Description: obj.Description,
				Aliases:     obj.XMitreAliases,
			})
		case "x-mitre-data-component":
			dcid := stixToExternal[obj.ID]
			if dcid == "" {
				dcid = obj.ID
			}

			dataComponents = append(dataComponents, DataComponent{
				ID:          dcid,
				StixID:      obj.ID,
				Name:        obj.Name,
				Description: obj.Description,
			})
		case "x-mitre-detection-strategy":
			detID := stixToExternal[obj.ID]
			if detID == "" {
				detID = obj.ID
			}

			detectionStrategies = append(detectionStrategies, DetectionStrategy{
				ID: detID,
				StixID: obj.ID,
				Name: obj.Name,
				Description: obj.Description,
				Analytics: obj.XMitreAnalyticRefs,
			})
		case "x-mitre-analytic":
			analyticID := stixToExternal[obj.ID]
			if analyticID == "" {
				analyticID = obj.ID
			}

			componentIDs := make([]string, 0)
			seenComponents := make(map[string]struct{})

			for _, ref := range analyticToComponentRefs[obj.ID] {
				componentID := stixToExternal[ref]
				if componentID == "" {
					componentID = ref
				}

				if _, exists := seenComponents[componentID]; exists {
					continue
				}

				seenComponents[componentID] = struct{}{}
				componentIDs = append(componentIDs, componentID)
			}

			analytics = append(analytics, Analytic{
				ID: analyticID,
				StixID: obj.ID,
				Name: obj.Name,
				Description: obj.Description,
				DataComponents: componentIDs,
			})
		}
	}

	derivedSeen := make(map[string]struct{})

	for _, obj := range bundle.Objects {
		if obj.XMitreDeprecated || obj.Revoked {
			continue
		}
		if obj.Type != "relationship" || obj.RelationshipType != "detects" {
			continue
		}

		dsRef := obj.SourceRef
		techRef := obj.TargetRef

		if !strings.HasPrefix(dsRef, "x-mitre-detection-strategy--") {
			continue
		}
		if !strings.HasPrefix(techRef, "attack-pattern--") {
			continue
		}
		techID := stixToExternal[techRef]
		if techID == "" || !hasIDPrefix(techID, "T") {
			continue
		}

		for _, text := range dsDetectionText[dsRef] {
			techDetectionText[techID] = appendUniqueText(techDetectionText[techID], text)
		}

		for _, analyticRef := range dsToAnalyticRefs[dsRef] {
			for _, text := range analyticDetectionText[analyticRef] {
				techDetectionText[techID] = appendUniqueText(techDetectionText[techID], text)
			}
		}

		componentRefs := dsToComponentRefs[dsRef]
		for _, dcRef := range componentRefs {
			dcID := stixToExternal[dcRef]
			if dcID == "" {
				dcID = dcRef
			}

			key := techID + "|" + dcID
			if _, ok := derivedSeen[key]; ok {
				continue
			}
			derivedSeen[key] = struct{}{}

			relationships = append(relationships, Relationship{
				Type:       "has_data_component",
				SourceType: "technique",
				SourceID:   techID,
				TargetType: "data_component",
				TargetID:   dcID,
			})
		}
	}

	for i := range techniques {
		parts := techDetectionText[techniques[i].ID]
		if len(parts) == 0 {
			continue
		}

		enriched := strings.Join(parts, "\n\n")
		if strings.TrimSpace(techniques[i].DetectionNotes) == "" {
			techniques[i].DetectionNotes = enriched
		} else {
			techniques[i].DetectionNotes += "\n\n" + enriched
		}
	}

	return CacheData{
		Techniques:     techniques,
		Groups:         groups,
		Mitigations:    mitigations,
		Relationships:  relationships,
		Softwares:      softwares,
		Campaigns:      campaigns,
		DataComponents: dataComponents,
		DetectionStrategies: detectionStrategies,
		Analytics: analytics,
	}, nil
}

func extractExternalID(refs []struct {
	SourceName string `json:"source_name"`
	ExternalID string `json:"external_id"`
}) string {
	for _, r := range refs {
		if r.SourceName == "mitre-attack" && r.ExternalID != "" {
			return r.ExternalID
		}
	}
	return ""
}

func hasIDPrefix(id, prefix string) bool {
	id = strings.ToUpper(strings.TrimSpace(id))
	prefix = strings.ToUpper(strings.TrimSpace(prefix))
	return strings.HasPrefix(id, prefix)
}

func appendUniqueText(parts []string, text string) []string {
	text = strings.TrimSpace(text)
	if text == "" {
		return parts
	}

	for _, p := range parts {
		if p == text {
			return parts
		}
	}

	return append(parts, text)
}

func saveCacheData(path string, cache CacheData) error {
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll("data", 0o755); err != nil {
		return err
	}

	return os.WriteFile(path, data, 0o644)
}

func loadCacheData(path string) (CacheData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return CacheData{}, err
	}

	var cache CacheData
	if err := json.Unmarshal(data, &cache); err != nil {
		return CacheData{}, err
	}

	return cache, nil
}
