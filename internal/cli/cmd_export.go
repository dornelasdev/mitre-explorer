package cli

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mitre-explorer/internal/attack"
)

type ExportOptions struct {
	Format      string
	Out         string
	For         string
	Target      string
	Matrix      string
	GeneratedAt string
	Meta        attack.UpdateMeta
}

func parseExportOptions(args []string) (ExportOptions, error) {
	opts := ExportOptions{
		Format: "csv",
	}

	for i := 0; i < len(args); i++ {
		if args[i] == "--format" || args[i] == "--out" || args[i] == "--for" {
			if _, err := optionValue(args, i); err != nil {
				return ExportOptions{}, err
			}
		}
		switch args[i] {
		case "--format":
			opts.Format = strings.ToLower(args[i+1])
			i++
		case "--out":
			opts.Out = args[i+1]
			i++
		case "--for":
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

func (app *App) handleExport(args []string) error {
	if len(args) < 2 {
		return invalidUsage("export requires a target and --out <file>")
	}
	target := normalizeListTarget(args[1])
	opts, err := parseExportOptions(args[2:])
	if err != nil {
		return invalidUsage("export: %v", err)
	}
	if err := validateExportTarget(target, opts); err != nil {
		return err
	}
	cache, err := app.loadCacheForCommand()
	if err != nil {
		return err
	}
	opts.Target = target
	opts.Matrix = app.activeMatrixName()
	opts.GeneratedAt = time.Now().Format("2006-01-02 15:04:05")
	opts.Meta, err = app.loadUpdateMetaForCommand()
	if err != nil {
		return err
	}
	headers, rows, err := app.exportRows(cache, target, opts)
	if err != nil {
		return err
	}
	if err := app.writeExportFile(opts, headers, rows); err != nil {
		return fmt.Errorf("write export: %w", err)
	}
	fmt.Fprintf(app.out, "%s wrote %d results row(s) from %s matrix to %s\n", app.ok("Exported"), len(rows), opts.Matrix, opts.Out)
	return nil
}

func (app *App) exportRows(cache attack.CacheData, target string, opts ExportOptions) ([]string, [][]string, error) {
	if err := validateExportTarget(target, opts); err != nil {
		return nil, nil, err
	}
	switch target {
	case "summary":
		rows := [][]string{
			{"Matrix", opts.Matrix},
			{"Generated At", opts.GeneratedAt},
			{"Cache File", app.matrix.CachePath},
			{"Metadata File", app.matrix.MetaPath},
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
		g, found := attack.FindGroup(cache, opts.For)
		if !found {
			return nil, nil, fmt.Errorf("group %q not found in cache", opts.For)
		}

		headers, rows := mappedTechniquesRows(
			g.ID,
			g.Name,
			attack.TechniquesUsedByGroup(cache, g.ID),
		)
		return headers, rows, nil

	case "mitigation-techniques":
		m, found := attack.FindMitigation(cache, opts.For)
		if !found {
			return nil, nil, fmt.Errorf("mitigation %q not found in cache", opts.For)
		}

		headers, rows := mappedTechniquesRows(
			m.ID,
			m.Name,
			attack.TechniquesMitigatedBy(cache, m.ID),
		)
		return headers, rows, nil

	case "software-techniques":
		s, found := attack.FindSoftware(cache, opts.For)
		if !found {
			return nil, nil, fmt.Errorf("software %q not found in cache", opts.For)
		}

		headers, rows := mappedTechniquesRows(
			s.ID,
			s.Name,
			attack.TechniquesUsedBySoftware(cache, s.ID),
		)
		return headers, rows, nil

	case "campaign-techniques":
		c, found := attack.FindCampaign(cache, opts.For)
		if !found {
			return nil, nil, fmt.Errorf("campaign %q not found in cache", opts.For)
		}

		headers, rows := mappedTechniquesRows(
			c.ID,
			c.Name,
			attack.TechniquesUsedByCampaign(cache, c.ID),
		)
		return headers, rows, nil

	case "detection-techniques":
		d, found := attack.FindDetectionStrategy(cache, opts.For)
		if !found {
			return nil, nil, fmt.Errorf("detection strategy %q not found in cache", opts.For)
		}

		headers, rows := mappedTechniquesRows(
			d.ID,
			d.Name,
			attack.TechniquesDetectedByStrategy(cache, d.ID),
		)
		return headers, rows, nil

	case "detection-analytics":
		d, found := attack.FindDetectionStrategy(cache, opts.For)
		if !found {
			return nil, nil, fmt.Errorf("detection strategy %q not found in cache", opts.For)
		}

		headers, rows := mappedAnalyticsRows(
			d.ID,
			d.Name,
			attack.AnalyticsByDetectionStrategy(cache, d.ID),
		)
		return headers, rows, nil

	case "detection-components":
		d, found := attack.FindDetectionStrategy(cache, opts.For)
		if !found {
			return nil, nil, fmt.Errorf("detection strategy %q not found in cache", opts.For)
		}

		headers, rows := mappedComponentsRows(
			d.ID,
			d.Name,
			attack.DataComponentsByDetectionStrategy(cache, d.ID),
		)
		return headers, rows, nil

	case "analytic-components":
		a, found := attack.FindAnalytic(cache, opts.For)
		if !found {
			return nil, nil, fmt.Errorf("analytic %q not found in cache", opts.For)
		}

		headers, rows := mappedComponentsRows(
			a.ID,
			a.Name,
			attack.DataComponentsByAnalytic(cache, a.ID),
		)
		return headers, rows, nil
	default:
		return nil, nil, fmt.Errorf("unknown export target: %s", target)
	}
}

func (app *App) writeExportFile(opts ExportOptions, headers []string, rows [][]string) (err error) {
	if opts.Format != "csv" && opts.Format != "md" {
		return fmt.Errorf("unsupported format: %s", opts.Format)
	}
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
	defer func() {
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
	}()

	switch opts.Format {
	case "csv":
		writer := csv.NewWriter(file)

		if err := writer.Write(headers); err != nil {
			return err
		}
		return writer.WriteAll(rows)

	case "md":
		_, err := file.WriteString(app.markdownReport(opts, headers, rows))
		return err

	default:
		return fmt.Errorf("unsupported format: %s", opts.Format)
	}
}

func mappedTechniquesRows(sourceID, sourceName string, techniques []attack.Technique) ([]string, [][]string) {
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

func mappedAnalyticsRows(sourceID, sourceName string, analytics []attack.Analytic) ([]string, [][]string) {
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

func mappedComponentsRows(sourceID, sourceName string, components []attack.DataComponent) ([]string, [][]string) {
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

func (app *App) markdownReport(opts ExportOptions, headers []string, rows [][]string) string {
	var b strings.Builder

	b.WriteString("# MITRE ATT&CK Export Report\n\n")
	b.WriteString("## Report Metadata\n\n")
	b.WriteString("| Field | Value |\n")
	b.WriteString("| --- | --- |\n")

	writeMarkdownMetadataRow(&b, "Matrix", opts.Matrix)
	writeMarkdownMetadataRow(&b, "Target", opts.Target)
	writeMarkdownMetadataRow(&b, "Generated At", opts.GeneratedAt)
	writeMarkdownMetadataRow(&b, "Cache File", app.matrix.CachePath)
	writeMarkdownMetadataRow(&b, "Metadata File", app.matrix.MetaPath)
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

func validateExportTarget(target string, opts ExportOptions) error {
	mapping := false
	switch target {
	case "summary", "techniques", "groups", "mitigations", "software", "campaigns", "detections", "analytics", "data-components":
	case "group-techniques", "mitigation-techniques", "software-techniques", "campaign-techniques", "detection-techniques", "detection-analytics", "detection-components", "analytic-components":
		mapping = true
	default:
		return invalidUsage("unknown export target: %s", target)
	}
	if mapping && opts.For == "" {
		return invalidUsage("--for is required for %s", target)
	}
	if !mapping && opts.For != "" {
		return invalidUsage("--for is only supported for mapped relationship exports")
	}
	return nil
}
