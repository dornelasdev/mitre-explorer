package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type ExportOptions struct {
	Format string
	Out string
	For string
	Target string
	GeneratedAt string
	Meta UpdateMeta
}

func parseExportOptions(args []string) (ExportOptions, error) {
	opts := ExportOptions{
		Format: "csv",
	}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--format":
			if i+1 >= len(args) {
				return ExportOptions{}, fmt.Errorf("--format requires csv or md")
			}
			opts.Format = strings.ToLower(args[i+1])
			i++
		case "--out":
			if i+1 >= len(args) {
				return ExportOptions{}, fmt.Errorf("--out requires a file path")
			}
			opts.Out = args[i+1]
			i++
		case "--for":
			if i+1 >= len(args) {
				return ExportOptions{}, fmt.Errorf("--for requires an id or name")
			}
			opts.For = args[i+1]
			i++
		default:
			return ExportOptions{}, fmt.Errorf("unknown export option: %s", args[i])
		}
	}
	
	if opts.Format != "csv" && opts.Format != "md" {
		return ExportOptions{}, fmt.Errorf("unsupported format: %s", opts.Format)
	}

	if opts.Out == "" {
		return ExportOptions{}, fmt.Errorf("--out is required")
	}

	return opts, nil
}

func handleExport(args []string) {
	if len(args) < 2 {
		printExportHelp()
		return
	}
	cache, cacheOK := loadCacheForCommand()
	if !cacheOK {
		return
	}

	target := strings.ToLower(args[1])
	if target != "summary" {
		target = normalizeListTarget(target)
	}

	opts, err := parseExportOptions(args[2:])
	if err != nil {
		fmt.Println(errText(err.Error()))
		fmt.Println("Usage: go run . export <target> --format csv|md --out <file>")
		return
	}

	opts.Target = target
	opts.GeneratedAt = time.Now().Format("2006-01-02 15:04:05")

	if meta, err := loadUpdateMeta(metaPath); err == nil {
		opts.Meta = meta
	}

	headers, rows, err := exportRows(cache, target, opts)
	if err != nil {
		fmt.Println(errText(err.Error()))
		return
	}

	if err := writeExportFile(opts, headers, rows); err != nil {
		fmt.Printf("Error writing export: %v\n", err)
		return
	}
	
	fmt.Printf("%s exported %d row(s) to %s\n", ok("Exported"), len(rows), opts.Out)
}

func exportRows(cache CacheData, target string, opts ExportOptions) ([]string, [][]string, error) {
	switch target {
	case "summary":
		rows := [][]string{
			{"Generated At", opts.GeneratedAt},
			{"Cache File", cachePath},
			{"Metadata File", metaPath},
			{"ETag", emptyFallback(opts.Meta.ETag)},
			{"Last Modified", emptyFallback(opts.Meta.LastModified)},
			{"Techniques", fmt.Sprintf("%d", len(cache.Techniques))},
			{"Groups", fmt.Sprintf("%d", len(cache.Groups))},
			{"Mitigations", fmt.Sprintf("%d", len(cache.Mitigations))},
			{"Software", fmt.Sprintf("%d", len(cache.Softwares))},
			{"Campaigns", fmt.Sprintf("%d", len(cache.Campaigns))},
			{"Detection Strategies", fmt.Sprintf("%d", len(cache.DetectionStrategies))},
			{"Analytics", fmt.Sprintf("%d", len(cache.Analytics))},
			{"Data Components", fmt.Sprintf("%d", len(cache.DataComponents))},
			{"Relationships", fmt.Sprintf("%d", len(cache.Relationships))},
		}
		return []string{"Field", "Value"}, rows, nil
	
	case "techniques":
		rows := make([][]string, 0, len(cache.Techniques))
		for _, t := range cache.Techniques {
			rows = append(rows, []string{
				t.ID,
				t.Name,
				strings.Join(t.Tactics, ", "),
				strings.Join(t.Platforms, ", "),
				strings.Join(t.DataComponents, ", "),
			})
		}
		return []string{"ID", "Name", "Tactics", "Platforms", "Data Components"}, rows, nil
	
	case "groups":
		rows := make([][]string, 0, len(cache.Groups))
		for _, g := range cache.Groups {
			rows = append(rows, []string{
				g.ID,
				g.Name,
				strings.Join(g.Aliases, ", "),
			})
		}
		return []string{"ID", "Name", "Aliases"}, rows, nil
	
	case "mitigations":
		rows := make([][]string, 0, len(cache.Mitigations))
		for _, m := range cache.Mitigations {
			rows = append(rows, []string{
				m.ID,
				m.Name,
			})
		}
		return []string{"ID", "Name"}, rows, nil
	
	case "software":
		rows := make([][]string, 0, len(cache.Softwares))
		for _, s := range cache.Softwares {
			rows = append(rows, []string{
				s.ID,
				s.Name,
				s.Type,
				strings.Join(s.Aliases, ", "),
			})
		}
		return []string{"ID", "Name", "Type", "Aliases"}, rows, nil
	

	case "campaigns":
		rows := make([][]string, 0, len(cache.Campaigns))
		for _, c := range cache.Campaigns {
			rows = append(rows, []string{
				c.ID,
				c.Name,
				strings.Join(c.Aliases, ", "),
			})
		}
		return []string{"ID", "Name", "Aliases"}, rows, nil
	
	case "detections":
		rows := make([][]string, 0, len(cache.DetectionStrategies))
		for _, d := range cache.DetectionStrategies {
			rows = append(rows, []string{
				d.ID,
				d.Name,
				fmt.Sprintf("%d", len(d.Analytics)),
			})
		}
		return []string{"ID", "Name", "Analytics"}, rows, nil
	
	case "analytics":
		rows := make([][]string, 0, len(cache.Analytics))
		for _, a := range cache.Analytics {
			rows = append(rows, []string{
				a.ID,
				a.Name,
				strings.Join(a.DataComponents, ", "),
			})
		}
		return []string{"ID", "Name", "Data Components"}, rows, nil
	
	case "data-components":
		rows := make([][]string, 0, len(cache.DataComponents))
		for _, dc := range cache.DataComponents {
			rows = append(rows, []string{
				dc.ID,
				dc.Name,
			})
		} 
		return []string{"ID", "Name"}, rows, nil

	case "group-techniques":
		if opts.For == "" {
			return nil, nil, fmt.Errorf("--for is required for group-techniques")
		}
		g, found := findGroup(cache, opts.For)
		if !found {
			return nil, nil, fmt.Errorf("group %q not found in cache", opts.For)
		}

		headers, rows := mappedTechniquesRows(
			g.ID,
			g.Name,
			techniquesUsedByGroup(cache, g.ID),
		)
		return headers, rows, nil
			
	case "mitigation-techniques":
		if opts.For == "" {
			return nil, nil, fmt.Errorf("--for is required for mitigation-techniques")
		}
		m, found := findMitigation(cache, opts.For)
		if !found {
			return nil, nil, fmt.Errorf("mitigation %q not found in cache", opts.For)
		}

		headers, rows := mappedTechniquesRows(
			m.ID,
			m.Name,
			techniquesMitigatedBy(cache, m.ID),
		)
		return headers, rows, nil

	case "software-techniques":
		if opts.For == "" {
			return nil, nil, fmt.Errorf("--for is required for software-techniques")
		}
		s, found := findSoftware(cache, opts.For)
		if !found {
			return nil, nil, fmt.Errorf("software %q not found in cache", opts.For)
		}

		headers, rows := mappedTechniquesRows(
			s.ID,
			s.Name,
			techniquesUsedBySoftware(cache, s.ID),
		)
		return headers, rows, nil

	case "campaign-techniques":
		if opts.For == "" {
			return nil, nil, fmt.Errorf("--for is required for campaign-techniques")
		}
		c, found := findCampaign(cache, opts.For)
		if !found {
			return nil, nil, fmt.Errorf("campaign %q not found in cache", opts.For)
		}
		
		headers, rows := mappedTechniquesRows(
			c.ID,
			c.Name,
			techniquesUsedByCampaign(cache, c.ID),
		)
		return headers, rows, nil

	case "detection-techniques":
		if opts.For == "" {
			return nil, nil, fmt.Errorf("--for is required for detection-techniques")
		}
		d, found := findDetectionStrategy(cache, opts.For)
		if !found {
			return nil, nil, fmt.Errorf("detection strategy %q not found in cache", opts.For)
		}
		
		headers, rows := mappedTechniquesRows(
			d.ID,
			d.Name,
			techniquesDetectedByStrategy(cache, d.ID),
		)
		return headers, rows, nil

	case "detection-analytics":
		if opts.For == "" {
			return nil, nil, fmt.Errorf("--for is required for detection-analytics")
		}
		d, found := findDetectionStrategy(cache, opts.For)
		if !found {
			return nil, nil, fmt.Errorf("detection strategy %q not found in cache", opts.For)
		}
		
		headers, rows := mappedAnalyticsRows(
			d.ID,
			d.Name,
			analyticsByDetectionStrategy(cache, d.ID),
		)
		return headers, rows, nil

	case "detection-components":
		if opts.For == "" {
			return nil, nil, fmt.Errorf("--for is required for detection-components")
		}
		d, found := findDetectionStrategy(cache, opts.For)
		if !found {
			return nil, nil, fmt.Errorf("detection strategy %q not found in cache", opts.For)
		}
		
		headers, rows := mappedComponentsRows(
			d.ID,
			d.Name,
			dataComponentsByDetectionStrategy(cache, d.ID),
		)
		return headers, rows, nil

	case "analytic-components":
		if opts.For == "" {
			return nil, nil, fmt.Errorf("--for is required for analytic-components")
		}
		a, found := findAnalytic(cache, opts.For)
		if !found {
			return nil, nil, fmt.Errorf("analytic %q not found in cache", opts.For)
		}
		
		headers, rows := mappedComponentsRows(
			a.ID,
			a.Name,
			dataComponentsByAnalytic(cache, a.ID),
		)
		return headers, rows, nil
	default:
		return nil, nil, fmt.Errorf("unknown export target: %s", target)
	}
}

func writeExportFile(opts ExportOptions, headers []string, rows [][]string) error {
	dir := filepath.Dir(opts.Out)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	file, err := os.Create(opts.Out)
	if err != nil {
		return err
	}
	defer file.Close()

	switch opts.Format {
	case "csv":
		writer := csv.NewWriter(file)
		defer writer.Flush()

		if err := writer.Write(headers); err != nil {
			return err
		}
		return writer.WriteAll(rows)
	
	case "md":
		_, err := file.WriteString(markdownReport(opts, headers, rows))
		return err
	
	default:
		return fmt.Errorf("unsupported format: %s", opts.Format)
	}
}

func mappedTechniquesRows(sourceID, sourceName string, techniques []Technique) ([]string, [][]string) {
	rows := make([][]string, 0, len(techniques))

	for _, t := range techniques {
		rows = append(rows, []string{
			sourceID,
			sourceName,
			t.ID,
			t.Name,
			strings.Join(t.Tactics, ", "),
			strings.Join(t.Platforms, ", "),
		})
	}
	return []string{"Source ID", "Source Name", "Technique ID", "Technique Name", "Tactics", "Platforms"}, rows
}

func mappedAnalyticsRows(sourceID, sourceName string, analytics []Analytic) ([]string, [][]string) {
	rows := make([][]string, 0, len(analytics))

	for _, a := range analytics {
		rows = append(rows, []string{
			sourceID,
			sourceName,
			a.ID,
			a.Name,
		})
	}
	return []string{"Source ID", "Source Name", "Analytic ID", "Analytic Name"}, rows
}

func mappedComponentsRows(sourceID, sourceName string, components []DataComponent) ([]string, [][]string) {
	rows := make([][]string, 0, len(components))

	for _, dc := range components {
		rows = append(rows, []string{
			sourceID,
			sourceName,
			dc.ID,
			dc.Name,
		})
	}
	return []string{"Source ID", "Source Name", "Data Component ID", "Data Component Name"}, rows
}

func markdownReport(opts ExportOptions, headers []string, rows [][]string) string {
	var b strings.Builder

	b.WriteString("# MITRE ATT&CK Cache Report\n\n")
	b.WriteString("## Report Metadata\n\n")
	b.WriteString("| Field | Value |\n")
	b.WriteString("| --- | --- |\n")

	writeMarkdownMetadataRow(&b, "Target", opts.Target)
	writeMarkdownMetadataRow(&b, "Generated At", opts.GeneratedAt)
	writeMarkdownMetadataRow(&b, "Cache File", cachePath)
	writeMarkdownMetadataRow(&b, "Metadata File", metaPath)
	writeMarkdownMetadataRow(&b, "ETag", emptyFallback(opts.Meta.ETag))
	writeMarkdownMetadataRow(&b, "Last Modified", emptyFallback(opts.Meta.LastModified))
	
	b.WriteString("\n## Results\n\n")
	b.WriteString(markdownTable(headers, rows))

	return b.String()
}

func markdownTable(headers []string, rows [][]string) string {
	var b strings.Builder

	b.WriteString("| ")
	b.WriteString(strings.Join(headers, " | "))
	b.WriteString(" |\n")
	
	b.WriteString("| ")
	for i := range headers {
		if i > 0 {
			b.WriteString(" | ")
		}
		b.WriteString("---")
	}
	b.WriteString(" |\n")

	for _, row := range rows {
		b.WriteString("| ")
		for i, cell := range row {
			if i > 0 {
				b.WriteString(" | ")
			}
			b.WriteString(markdownCell(cell))
		}
		b.WriteString(" |\n")
	}
	return b.String()
}

func writeMarkdownMetadataRow(b *strings.Builder, field, value string) {
	b.WriteString("| ")
	b.WriteString(markdownCell(field))
	b.WriteString(" | ")
	b.WriteString(markdownCell(value))
	b.WriteString(" |\n")
}


func markdownCell(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}

