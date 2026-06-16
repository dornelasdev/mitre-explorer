package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func startSpinner(message string) func() {
	done := make(chan struct{})

	go func() {
		frames := []rune{'|', '/', '-', '\\'}
		i := 0
		for {
			select {
			case <-done:
				fmt.Printf("\r%s... done\n", message)

				return
			default:
				fmt.Printf("\r%s... %c", message, frames[i%len(frames)])
				time.Sleep(120 * time.Millisecond)
				i++
			}
		}
	}()

	return func() { close(done) }
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

var useColor = true

func title(text string) string {
	if !useColor {
		return text
	}
	return cBold + cCyan + text + cReset
}

func ok(text string) string {
	if !useColor {
		return text
	}
	return cGreen + text + cReset
}

func warn(text string) string {
	if !useColor {
		return text
	}
	return cYellow + text + cReset
}

func errText(text string) string {
	if !useColor {
		return text
	}
	return cRed + text + cReset
}

func label(text string) string {
	if !useColor {
		return text
	}
	return cBold + text + cReset
}

func printTechniqueTable(techniques []Technique) {
	const nameWidth = 72

	rows := make([][]string, 0, len(techniques))
	for i, t := range techniques {
		rows = append(rows, []string{
			strconv.Itoa(i + 1),
			t.ID,
			truncateText(t.Name, nameWidth),
		})
	}

	printEntityTable(
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

func printDivider(width int) {
	fmt.Println(strings.Repeat("-", width))
}

func printEntityTable(headers []string, rows [][]string, widths []int) {
	for i, h := range headers {
		if i == len(headers)-1 {
			fmt.Printf("%s", h)
			continue
		}
		fmt.Printf("%-*s ", widths[i], h)
	}
	fmt.Println()

	totalWidth := 0
	for _, w := range widths {
		totalWidth += w + 1
	}
	printDivider(totalWidth)

	for _, row := range rows {
		for i, cell := range row {
			if i == len(row)-1 {
				fmt.Printf("%s", cell)
				continue
			}
			fmt.Printf("%-*s ", widths[i], cell)
		}
		fmt.Println()
	}
}

func printGroupTable(groups []Group) {
	rows := make([][]string, 0, len(groups))
	for i, g := range groups {
		rows = append(rows, []string{
			strconv.Itoa(i + 1),
			g.ID,
			truncateText(g.Name, 48),
		})
	}

	printEntityTable(
		[]string{"#", "ID", "Name"},
		rows,
		[]int{4, 10, 48},
	)
}

func printMitigationTable(mitigations []Mitigation) {
	rows := make([][]string, 0, len(mitigations))
	for i, m := range mitigations {
		rows = append(rows, []string{
			strconv.Itoa(i + 1),
			m.ID,
			truncateText(m.Name, 48),
		})
	}

	printEntityTable(
		[]string{"#", "ID", "Name"},
		rows,
		[]int{4, 10, 48},
	)
}

func printSoftwareTable(softwares []Software) {
	rows := make([][]string, 0, len(softwares))
	for i, s := range softwares {
		rows = append(rows, []string{
			strconv.Itoa(i + 1),
			s.ID,
			truncateText(s.Name, 48),
		})
	}

	printEntityTable(
		[]string{"#", "ID", "Name"},
		rows,
		[]int{4, 10, 48},
	)
}

func printCampaignTable(campaigns []Campaign) {
	rows := make([][]string, 0, len(campaigns))
	for i, c := range campaigns {
		rows = append(rows, []string{
			strconv.Itoa(i + 1),
			c.ID,
			truncateText(c.Name, 48),
		})
	}

	printEntityTable(
		[]string{"#", "ID", "Name"},
		rows,
		[]int{4, 10, 48},
	)
}

func printDataComponentList(components []DataComponent) {
	rows := make([][]string, 0, len(components))
	for i, dc := range components {
		rows = append(rows, []string{
			strconv.Itoa(i + 1),
			truncateText(dc.Name, 56),
		})
	}

	printEntityTable(
		[]string{"#", "Name"},
		rows,
		[]int{4, 56},
	)
}

func printDetectionTable(detections []DetectionStrategy) {
	rows := make([][]string, 0, len(detections))
	for i, d := range detections {
		rows = append(rows, []string{
			strconv.Itoa(i + 1),
			d.ID,
			truncateText(d.Name, 56),
		})
	}

	printEntityTable(
		[]string{"#", "ID", "Name"},
		rows,
		[]int{4, 12, 56},
	)
}

func printAnalyticList(analytics []Analytic) {
	rows := make([][]string, 0, len(analytics))
	for i, d := range analytics {
		rows = append(rows, []string{
			strconv.Itoa(i + 1),
			d.ID,
			truncateText(d.Name, 56),
		})
	}

	printEntityTable(
		[]string{"#", "ID", "Name"},
		rows,
		[]int{4, 12, 56},
	)
}

type DetailField struct {
	Label string
	Value string
}

func printDetails(fields []DetailField) {
	for _, f := range fields {
		fmt.Printf("%s %s\n", label(f.Label), f.Value)
	}
}

func printInvalidSelection() {
	fmt.Println("Invalid selection.")
}

func printNoResults(item string) {
	fmt.Printf("No %s found.\n", item)
}

func printNoMappedResults(item string, source string) {
	fmt.Printf("No %s mapped for this %s.\n", item, source)
}

func printSection(text string) {
	fmt.Println()
	fmt.Println(title(text))
	printDivider(64)
}

func printSubsection(text string) {
	fmt.Println()
	fmt.Println(label(text))
	printDivider(40)
}

func printPaginatedTable(titleText string, headers []string, rows [][]string, widths []int, pageSize int) {
	if pageSize <= 0 {
		pageSize = 25
	}

	if len(rows) == 0 {
		printNoResults(strings.ToLower(titleText))
		return
	}

	reader := bufio.NewReader(os.Stdin)
	page := 0
	totalPages := (len(rows) + pageSize - 1) / pageSize

	for {
		start := page * pageSize
		end := start + pageSize
		if end > len(rows) {
			end = len(rows)
		}

		printSection(titleText)
		fmt.Printf("Showing %d-%d of %d\n", start+1, end, len(rows))
		printEntityTable(headers, rows[start:end], widths)
		fmt.Println()
		fmt.Println("[n] Next  [p] Previous  [q] Quit")
		fmt.Print("> ")

		input := strings.ToLower(strings.TrimSpace(readLine(reader)))

		switch input {
		case "n":
			if page < totalPages-1 {
				page++
			} else {
				fmt.Println("Already on last page.")
			}
		case "p":
			if page > 0 {
				page--
			} else {
				fmt.Println("Already on first page.")
			}
		case "q":
			return
		default:
			printInvalidSelection()
		}
	}
}
