package cli

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"mitre-explorer/internal/attack"
)

func (app *App) printMappedTechniquesWithMode(results []attack.Technique, detailed bool) {
	if detailed {
		for i, t := range results {
			fmt.Fprintf(app.out, "\n[%d] %s | %s\n", i+1, t.ID, t.Name)
			fmt.Fprintf(app.out, "    Tactics: %s\n", strings.Join(t.Tactics, ", "))
			fmt.Fprintf(app.out, "    Platforms: %s\n", strings.Join(t.Platforms, ", "))
		}
		return
	}
	app.printTechniqueTable(results)
}

func (app *App) startSpinner(message string) func() {
	done := make(chan struct{})
	finished := make(chan struct{})

	go func() {
		defer close(finished)
		ticker := time.NewTicker(120 * time.Millisecond)
		defer ticker.Stop()
		frames := []rune{'|', '/', '-', '\\'}
		i := 0
		for {
			fmt.Fprintf(app.out, "\r%s... %c", message, frames[i%len(frames)])
			i++
			select {
			case <-done:
				fmt.Fprintf(app.out, "\r%s... done\n", message)

				return
			case <-ticker.C:
			}
		}
	}()

	var stopOnce sync.Once
	return func() {
		stopOnce.Do(func() { close(done) })
		<-finished
	}
}

func humanSize(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cCyan   = "\033[36m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cRed    = "\033[31m"
)

func (app *App) title(text string) string {
	if !app.useColor {
		return text
	}
	return cBold + cCyan + text + cReset
}

func (app *App) ok(text string) string {
	if !app.useColor {
		return text
	}
	return cGreen + text + cReset
}

func (app *App) warn(text string) string {
	if !app.useColor {
		return text
	}
	return cYellow + text + cReset
}

func (app *App) errText(text string) string {
	if !app.useColor {
		return text
	}
	return cRed + text + cReset
}

func (app *App) label(text string) string {
	if !app.useColor {
		return text
	}
	return cBold + text + cReset
}

func (app *App) printTechniqueTable(techniques []attack.Technique) {
	const nameWidth = 72

	rows := make([][]string, 0, len(techniques))
	for i, t := range techniques {
		rows = append(rows, []string{
			strconv.Itoa(i + 1),
			t.ID,
			truncateText(t.Name, nameWidth),
		})
	}

	app.printEntityTable(
		[]string{"#", "ID", "Name"},
		rows,
		[]int{4, 12, nameWidth},
	)
}

func truncateText(s string, max int) string {
	if max <= 0 {
		return s
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max <= 1 {
		return "..."
	}
	return string(r[:max-1]) + "..."
}

func (app *App) printDivider(width int) {
	fmt.Fprintln(app.out, strings.Repeat("-", width))
}

func (app *App) printEntityTable(headers []string, rows [][]string, widths []int) {
	for i, h := range headers {
		if i == len(headers)-1 {
			fmt.Fprintf(app.out, "%s", h)
			continue
		}
		fmt.Fprintf(app.out, "%-*s ", widths[i], h)
	}
	fmt.Fprintln(app.out)

	totalWidth := 0
	for _, w := range widths {
		totalWidth += w + 1
	}
	app.printDivider(totalWidth)

	for _, row := range rows {
		for i, cell := range row {
			if i == len(row)-1 {
				fmt.Fprintf(app.out, "%s", cell)
				continue
			}
			fmt.Fprintf(app.out, "%-*s ", widths[i], cell)
		}
		fmt.Fprintln(app.out)
	}
}

func (app *App) printGroupTable(groups []attack.Group) {
	rows := make([][]string, 0, len(groups))
	for i, g := range groups {
		rows = append(rows, []string{
			strconv.Itoa(i + 1),
			g.ID,
			truncateText(g.Name, 48),
		})
	}

	app.printEntityTable(
		[]string{"#", "ID", "Name"},
		rows,
		[]int{4, 10, 48},
	)
}

func (app *App) printMitigationTable(mitigations []attack.Mitigation) {
	rows := make([][]string, 0, len(mitigations))
	for i, m := range mitigations {
		rows = append(rows, []string{
			strconv.Itoa(i + 1),
			m.ID,
			truncateText(m.Name, 48),
		})
	}

	app.printEntityTable(
		[]string{"#", "ID", "Name"},
		rows,
		[]int{4, 10, 48},
	)
}

func (app *App) printSoftwareTable(softwares []attack.Software) {
	rows := make([][]string, 0, len(softwares))
	for i, s := range softwares {
		rows = append(rows, []string{
			strconv.Itoa(i + 1),
			s.ID,
			truncateText(s.Name, 48),
		})
	}

	app.printEntityTable(
		[]string{"#", "ID", "Name"},
		rows,
		[]int{4, 10, 48},
	)
}

func (app *App) printCampaignTable(campaigns []attack.Campaign) {
	rows := make([][]string, 0, len(campaigns))
	for i, c := range campaigns {
		rows = append(rows, []string{
			strconv.Itoa(i + 1),
			c.ID,
			truncateText(c.Name, 48),
		})
	}

	app.printEntityTable(
		[]string{"#", "ID", "Name"},
		rows,
		[]int{4, 10, 48},
	)
}

func (app *App) printDataComponentList(components []attack.DataComponent) {
	rows := make([][]string, 0, len(components))
	for i, dc := range components {
		rows = append(rows, []string{
			strconv.Itoa(i + 1),
			truncateText(dc.Name, 56),
		})
	}

	app.printEntityTable(
		[]string{"#", "Name"},
		rows,
		[]int{4, 56},
	)
}

func (app *App) printDetectionTable(detections []attack.DetectionStrategy) {
	rows := make([][]string, 0, len(detections))
	for i, d := range detections {
		rows = append(rows, []string{
			strconv.Itoa(i + 1),
			d.ID,
			truncateText(d.Name, 56),
		})
	}

	app.printEntityTable(
		[]string{"#", "ID", "Name"},
		rows,
		[]int{4, 12, 56},
	)
}

func (app *App) printAnalyticList(analytics []attack.Analytic) {
	rows := make([][]string, 0, len(analytics))
	for i, d := range analytics {
		rows = append(rows, []string{
			strconv.Itoa(i + 1),
			d.ID,
			truncateText(d.Name, 56),
		})
	}

	app.printEntityTable(
		[]string{"#", "ID", "Name"},
		rows,
		[]int{4, 12, 56},
	)
}

type DetailField struct {
	Label string
	Value string
}

func (app *App) printDetails(fields []DetailField) {
	for _, f := range fields {
		fmt.Fprintf(app.out, "%s %s\n", app.label(f.Label), f.Value)
	}
}

func (app *App) printInvalidSelection() {
	fmt.Fprintln(app.out, "Invalid selection.")
}

func (app *App) printNoResults(item string) {
	fmt.Fprintf(app.out, "No %s found.\n", item)
}

func (app *App) printNoMappedResults(item string, source string) {
	fmt.Fprintf(app.out, "No %s mapped for this %s.\n", item, source)
}

func (app *App) printSection(text string) {
	fmt.Fprintln(app.out)
	fmt.Fprintln(app.out, app.title(text))
	app.printDivider(64)
}

func (app *App) printSubsection(text string) {
	fmt.Fprintln(app.out)
	fmt.Fprintln(app.out, app.label(text))
	app.printDivider(40)
}

func (app *App) printPaginatedTable(titleText string, headers []string, rows [][]string, widths []int, pageSize int) {
	if pageSize <= 0 {
		pageSize = 25
	}

	if len(rows) == 0 {
		app.printNoResults(strings.ToLower(titleText))
		return
	}

	reader := app.reader
	page := 0
	totalPages := (len(rows) + pageSize - 1) / pageSize

	for {
		start := page * pageSize
		end := start + pageSize
		if end > len(rows) {
			end = len(rows)
		}

		app.printSection(titleText)
		fmt.Fprintf(app.out, "Showing %d-%d of %d\n", start+1, end, len(rows))
		app.printEntityTable(headers, rows[start:end], widths)
		fmt.Fprintln(app.out)
		fmt.Fprintln(app.out, "[n] Next  [p] Previous  [q] Quit")
		fmt.Fprint(app.out, "> ")

		input, err := readLine(reader)
		if err != nil {
			return
		}
		input = strings.ToLower(input)

		switch input {
		case "":
			return
		case "n":
			if page < totalPages-1 {
				page++
			} else {
				fmt.Fprintln(app.out, "Already on last page.")
			}
		case "p":
			if page > 0 {
				page--
			} else {
				fmt.Fprintln(app.out, "Already on first page.")
			}
		case "q":
			return
		default:
			app.printInvalidSelection()
		}
	}
}
