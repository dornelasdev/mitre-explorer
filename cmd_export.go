package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type ExportOptions struct {
	Format string
	Out string
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
		fmt.Println("Usage: go run . export <target> --format csv|md --out <file>")
		fmt.Println("Targets: summary | techniques | groups | mitigations | software | campaigns | detections | analytics | data-components")
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

	headers, rows, err := exportRows(cache, target)
	if err != nil {
		fmt.Println(errText(err.Error()))
		return
	}

	if err := writeExportFile(opts.Out, opts.Format, headers, rows); err != nil {
		fmt.Printf("Error writing export: %v\n", err)
		return
	}
	
	fmt.Printf("%s exported %d row(s) to %s\n", ok("Exported"), len(rows), opts.Out)
}

func exportRows(cache CacheData, target string) ([]string, [][]string, error) {
	switch target {
	case "summary":
		return []string{"Target", "Count"}, [][]string{
			{"Techniques", fmt.Sprintf("%d", len(cache.Techniques))},
			{"Groups", fmt.Sprintf("%d", len(cache.Groups))},
			{"Mitigations", fmt.Sprintf("%d", len(cache.Mitigations))},
			{"Software", fmt.Sprintf("%d", len(cache.Softwares))},
			{"Campaigns", fmt.Sprintf("%d", len(cache.Campaigns))},
			{"Detection Strategies", fmt.Sprintf("%d", len(cache.DetectionStrategies))},
			{"Analytics", fmt.Sprintf("%d", len(cache.Analytics))},
			{"Data Components", fmt.Sprintf("%d", len(cache.DataComponents))},
			{"Relationships", fmt.Sprintf("%d", len(cache.Relationships))},
		}, nil
	
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

	default:
		return nil, nil, fmt.Errorf("unknown export target: %s", target)
	}
}

func writeExportFile(path, format string, headers []string, rows [][]string) error {
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	switch format {
	case "csv":
		writer := csv.NewWriter(file)
		defer writer.Flush()

		if err := writer.Write(headers); err != nil {
			return err
		}
		return writer.WriteAll(rows)
	
	case "md":
		_, err := file.WriteString(markdownTable(headers, rows))
		return err
	
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
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

func markdownCell(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}

