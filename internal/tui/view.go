package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

const wideBanner = ` __  __ ___ _____ ____  _____    _____  __  __ ____  _      ___  ____  _____ ____
|  \/  |_ _|_   _|  _ \| ____|  | ____| \ \/ /|  _ \| |    / _ \|  _ \| ____|  _ \
| |\/| || |  | | | |_) |  _|    |  _|    \  / | |_) | |   | | | | |_) |  _| | |_) |
| |  | || |  | | |  _ <| |___   | |___   /  \ |  __/| |___| |_| |  _ <| |___|  _ <
|_|  |_|___| |_| |_| \_\_____|  |_____| /_/\_\|_|   |_____|\___/|_| \_\_____|_| \_\`

const compactBanner = "MITRE EXPLORER"

func (m model) View() tea.View {
	view := tea.NewView(m.render())
	view.AltScreen = true
	view.WindowTitle = "MITRE Explorer"
	return view
}

func (m model) render() string {
	width, height := m.width, m.height
	if width == 0 {
		width = 100
	}
	if height == 0 {
		height = 30
	}

	if width < 36 || height < 10 {
		return m.renderSmall(width, height)
	}
	if width >= 76 && height >= 18 {
		return m.renderWide(width, height)
	}
	return m.renderCompact(width, height)
}

func (m model) renderWide(width, height int) string {
	leftWidth := 34
	rightWidth := width - leftWidth - 4
	bodyHeight := max(7, height-13)

	left := m.panelStyle(leftWidth, bodyHeight).Render(m.leftPanel(bodyHeight-2, leftWidth-4))
	right := m.panelStyle(rightWidth, bodyHeight).Render(m.rightPanel(rightWidth-4, bodyHeight-2))
	header := compactBanner
	if width >= 100 && height >= 24 {
		header = wideBanner
	}

	return strings.Join([]string{
		m.titleStyle().Render(header),
		m.statusLine(),
		"",
		lipgloss.JoinHorizontal(lipgloss.Top, left, right),
		"",
		m.footer(),
	}, "\n")
}

func (m model) renderCompact(width, height int) string {
	panelWidth := max(30, width-4)
	panelHeight := max(5, height-7)
	return strings.Join([]string{
		m.titleStyle().Render(compactBanner),
		truncateText(m.statusLine(), width),
		"",
		m.panelStyle(panelWidth, panelHeight).Render(m.singlePanel(panelWidth-4, panelHeight-2)),
		"",
		m.footer(),
	}, "\n")
}

func (m model) renderSmall(width, height int) string {
	return fmt.Sprintf("%s\nTerminal too small (%dx%d). Resize to at least 36x10.\n%s",
		compactBanner, width, height, m.footer())
}

func (m model) leftPanel(maxRows, width int) string {
	if m.loading {
		return m.headingStyle().Render("LOADING CACHE")
	}
	if m.loadErr != nil {
		return m.headingStyle().Render("CACHE UNAVAILABLE")
	}

	current := m.displayListPage()
	if current == nil {
		return ""
	}
	labels := make([]string, 0, len(current.items))
	for _, item := range current.items {
		labels = append(labels, itemLabel(item))
	}
	return m.listContent(current.title, labels, current.cursor, maxRows, width)
}

func (m model) rightPanel(width, height int) string {
	var content string
	offset := 0
	if m.loading {
		content = strings.Join([]string{
			m.headingStyle().Render("LOADING CACHE"),
			"",
			"Reading the selected matrix cache...",
		}, "\n")
	} else if m.loadErr != nil {
		content = strings.Join([]string{
			m.headingStyle().Render("CACHE UNAVAILABLE"),
			"",
			m.loadErr.Error(),
			"",
			fmt.Sprintf("Run: go run . update --matrix %s", m.options.Matrix),
		}, "\n")
	} else if m.search.active {
		content = m.searchContent()
	} else {
		content = m.contextContent()
		if active := m.activePage(); active != nil && active.kind == pageDetail {
			offset = active.offset
		}
	}

	return renderViewport(content, width, height, offset)
}

func (m model) singlePanel(width, height int) string {
	active := m.activePage()
	if m.loading || m.loadErr != nil || m.search.active || (active != nil && active.kind == pageDetail) {
		return m.rightPanel(width, height)
	}
	return m.leftPanel(height, width)
}

func (m model) searchContent() string {
	scope := searchScopes[m.search.scope]
	lines := []string{
		m.headingStyle().Render("SEARCH"),
		"",
		"Scope: " + scope.name,
		m.search.input.View(),
		"",
	}
	query := strings.TrimSpace(m.search.input.Value())
	if query == "" {
		lines = append(lines, "Type a query to search the local cache.")
		return strings.Join(lines, "\n")
	}
	lines = append(lines, fmt.Sprintf("%d result(s)", len(m.search.results)))
	for index := 0; index < min(4, len(m.search.results)); index++ {
		lines = append(lines, "  "+itemLabel(m.search.results[index]))
	}
	return strings.Join(lines, "\n")
}

func (m model) contextContent() string {
	active := m.activePage()
	if active == nil {
		return m.headingStyle().Render("NO CONTENT")
	}
	if active.kind == pageDetail {
		return m.itemDetails(active.detail, active.relations)
	}

	item, ok := selectedPageItem(*active)
	if !ok {
		return m.headingStyle().Render("NO ITEMS") + "\n\nNothing is available in this section."
	}
	if item.kind == itemCategory || item.kind == itemTactic || item.kind == itemRelation {
		unit := "item(s)"
		if item.kind == itemTactic {
			unit = "technique(s)"
		}
		return strings.Join([]string{
			m.headingStyle().Render(item.name),
			"",
			fmt.Sprintf("%d %s", item.count, unit),
			"",
			"Press Enter to browse.",
		}, "\n")
	}

	return strings.Join([]string{
		m.headingStyle().Render(item.name),
		"",
		"ID: " + item.id,
		"",
		"Press Enter for full details.",
	}, "\n")
}

func (m model) itemDetails(item browseItem, relations []browseItem) string {
	description := strings.TrimSpace(item.description)
	if description == "" {
		description = "Not available"
	}
	lines := []string{
		m.headingStyle().Render(itemKindTitle(item.kind) + " DETAILS"),
		"",
		item.id + "  " + item.name,
	}
	for _, field := range item.fields {
		value := strings.TrimSpace(field.value)
		if value == "" {
			value = "Not available"
		}
		lines = append(lines, field.label+": "+value)
	}
	lines = append(lines,
		"",
		"Description:",
		description,
	)
	if len(relations) == 1 {
		lines = append(lines, "", fmt.Sprintf("Enter: %s (%d)", relations[0].name, relations[0].count))
	} else if len(relations) > 1 {
		lines = append(lines, "", "Enter: view mappings")
	}
	return strings.Join(lines, "\n")
}

func (m model) displayListPage() *page {
	if len(m.pages) == 0 {
		return nil
	}
	index := len(m.pages) - 1
	if m.pages[index].kind == pageDetail {
		index--
	}
	if index < 0 || m.pages[index].kind != pageList {
		return nil
	}
	return &m.pages[index]
}

func itemLabel(item browseItem) string {
	switch item.kind {
	case itemCategory, itemTactic, itemRelation:
		return fmt.Sprintf("%s (%d)", item.name, item.count)
	default:
		return strings.TrimSpace(item.id + "  " + item.name)
	}
}

func itemKindTitle(kind itemKind) string {
	switch kind {
	case itemTechnique:
		return "TECHNIQUE"
	case itemGroup:
		return "GROUP"
	case itemMitigation:
		return "MITIGATION"
	case itemSoftware:
		return "SOFTWARE"
	case itemCampaign:
		return "CAMPAIGN"
	case itemDetection:
		return "DETECTION STRATEGY"
	case itemAnalytic:
		return "ANALYTIC"
	case itemDataComponent:
		return "DATA COMPONENT"
	default:
		return "ITEM"
	}
}

func (m model) listContent(title string, items []string, cursor, maxRows, width int) string {
	lines := []string{m.headingStyle().Render(title), ""}
	if len(items) == 0 {
		return strings.Join(append(lines, "No items found."), "\n")
	}

	available := max(1, maxRows-len(lines))
	start, end := visibleRange(len(items), cursor, available)
	for index := start; index < end; index++ {
		prefix := "  "
		if index == cursor {
			prefix = "> "
		}
		line := fmt.Sprintf("%s%2d  %s", prefix, index+1, items[index])
		line = truncateText(line, width)
		if index == cursor {
			line = m.selectedStyle().Render(line)
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func visibleRange(length, cursor, size int) (int, int) {
	if length <= size {
		return 0, length
	}
	start := cursor - size/2
	start = min(max(start, 0), length-size)
	return start, start + size
}

func truncateText(value string, width int) string {
	if width <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= width {
		return value
	}
	if width <= 3 {
		return string(runes[:width])
	}
	return string(runes[:width-3]) + "..."
}

func joinedOrUnavailable(values []string) string {
	if len(values) == 0 {
		return "Not available"
	}
	return strings.Join(values, ", ")
}

func (m model) statusLine() string {
	return fmt.Sprintf("Matrix: %s  Cache: %s  Version: %s",
		m.options.Matrix, m.options.CachePath, m.options.Version)
}

func (m model) footer() string {
	var text string
	active := m.activePage()
	switch {
	case m.loading || m.loadErr != nil:
		text = "q / Esc / Ctrl+C  quit"
	case m.search.active:
		text = "Tab / Shift+Tab  scope    Enter  results    Esc  cancel    Ctrl+C  quit"
	case len(m.pages) <= 1:
		text = "up/k down/j  move    Enter  select    q/Esc  quit"
	case active != nil && active.kind == pageDetail && len(active.relations) == 0:
		text = "up/k down/j  scroll    b/Esc  back    q  quit"
	case active != nil && active.kind == pageDetail:
		text = "up/k down/j  scroll    Enter  mappings    b/Esc  back    q  quit"
	default:
		text = "up/k down/j  move    Enter  select    b/Esc  back    q  quit"
	}
	return m.mutedStyle().Render(text)
}

func (m model) detailMaxOffset(current page) int {
	width, height := m.detailViewportSize()
	content := m.itemDetails(current.detail, current.relations)
	wrapped := lipgloss.NewStyle().Width(width).MaxWidth(width).Render(content)
	return max(0, len(strings.Split(wrapped, "\n"))-height)
}

func (m model) detailViewportSize() (int, int) {
	width, height := m.width, m.height
	if width == 0 {
		width = 100
	}
	if height == 0 {
		height = 30
	}
	if width >= 76 && height >= 18 {
		leftWidth := 34
		rightWidth := width - leftWidth - 4
		return rightWidth - 4, max(7, height-13) - 2
	}
	panelWidth := max(30, width-4)
	panelHeight := max(5, height-7)
	return panelWidth - 4, panelHeight - 2
}

func renderViewport(content string, width, height, offset int) string {
	wrapped := lipgloss.NewStyle().Width(width).MaxWidth(width).Render(content)
	lines := strings.Split(wrapped, "\n")
	offset = min(max(offset, 0), max(0, len(lines)-height))
	end := min(offset+height, len(lines))
	return strings.Join(lines[offset:end], "\n")
}

func (m model) titleStyle() lipgloss.Style {
	style := lipgloss.NewStyle()
	if !m.options.Plain {
		style = style.Bold(true).Foreground(lipgloss.Color("#58C7D9"))
	}
	return style
}

func (m model) headingStyle() lipgloss.Style {
	style := lipgloss.NewStyle()
	if !m.options.Plain {
		style = style.Bold(true).Foreground(lipgloss.Color("#E8B04A"))
	}
	return style
}

func (m model) selectedStyle() lipgloss.Style {
	style := lipgloss.NewStyle()
	if !m.options.Plain {
		style = style.Bold(true).Foreground(lipgloss.Color("#58C7D9"))
	}
	return style
}

func (m model) mutedStyle() lipgloss.Style {
	style := lipgloss.NewStyle()
	if !m.options.Plain {
		style = style.Foreground(lipgloss.Color("#80878F"))
	}
	return style
}

func (m model) panelStyle(width, height int) lipgloss.Style {
	style := lipgloss.NewStyle().
		Border(lipgloss.ASCIIBorder()).
		Padding(0, 1).
		Width(width).
		Height(height).
		MaxWidth(width).
		MaxHeight(height)
	if !m.options.Plain {
		style = style.BorderForeground(lipgloss.Color("#3B8793"))
	}
	return style
}
