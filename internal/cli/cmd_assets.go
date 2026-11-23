package cli

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"mitre-explorer/internal/attack"
	"mitre-explorer/internal/detailtext"
)

func (app *App) requireICSAssets() error {
	if app.activeMatrixName() != "ics" {
		return invalidUsage("assets are only available with --matrix ics")
	}
	return nil
}

func (app *App) handleAsset(args []string) error {
	flags, err := entityOptions("asset", args)
	if err != nil {
		return err
	}
	if err := app.requireICSAssets(); err != nil {
		return err
	}
	cache, err := app.loadCacheForCommand()
	if err != nil {
		return err
	}
	if len(cache.Assets) == 0 {
		return errors.New(detailtext.AssetCacheHint)
	}
	asset, found := attack.FindAsset(cache, args[1])
	if !found {
		return fmt.Errorf("asset %q not found in the ICS cache", args[1])
	}
	techniques := attack.TechniquesTargetingAsset(cache, asset.ID)
	app.printAssetDetails(asset, len(techniques))
	if flags.Techniques {
		app.printSubsection("Mapped Techniques")
		app.printTechniqueMapping("asset", techniques, flags.Detailed)
	}
	return nil
}

func (app *App) printAssetDetails(asset attack.Asset, techniqueCount int) {
	app.printSection("Asset Details")
	fields := []DetailField{{"ID:", asset.ID}, {"Name:", asset.Name}}
	if platforms := strings.Join(asset.Platforms, ", "); platforms != "" {
		fields = append(fields, DetailField{"Platforms:", platforms})
	}
	if sectors := strings.Join(asset.Sectors, ", "); sectors != "" {
		fields = append(fields, DetailField{"Sectors:", sectors})
	}
	app.printDetails(append(fields,
		DetailField{"Mapped techniques:", strconv.Itoa(techniqueCount)},
		DetailField{"Description:", asset.Description},
	))
	app.printDetailSections(detailtext.AssetSections(asset))
}

func sortedAssets(assets []attack.Asset) []attack.Asset {
	out := slices.Clone(assets)
	slices.SortFunc(out, func(a, b attack.Asset) int { return strings.Compare(a.ID, b.ID) })
	return out
}

func assetRows(assets []attack.Asset, numbered bool) [][]string {
	rows := make([][]string, 0, len(assets))
	for i, asset := range assets {
		row := []string{asset.ID, truncateText(asset.Name, 60)}
		if numbered {
			row = append([]string{strconv.Itoa(i + 1)}, row...)
		}
		rows = append(rows, row)
	}
	return rows
}

func (app *App) printAssetTable(assets []attack.Asset) {
	app.printEntityTable([]string{"#", "ID", "Name"}, assetRows(assets, true), []int{4, 10, 60})
}

func (app *App) runGuidedAssets(cache attack.CacheData) {
	if len(cache.Assets) == 0 {
		fmt.Fprintln(app.out, detailtext.AssetCacheHint)
		return
	}
	assets := sortedAssets(cache.Assets)
	for {
		app.printSection("Assets")
		app.printAssetTable(assets)
		fmt.Fprint(app.out, "  [q] Return to guided menu\n> ")
		input, err := readLine(app.reader)
		if err != nil || strings.EqualFold(input, "q") {
			return
		}
		index, err := strconv.Atoi(input)
		if err != nil || index < 1 || index > len(assets) {
			app.printInvalidSelection()
			continue
		}

		asset := assets[index-1]
		techniques := attack.TechniquesTargetingAsset(cache, asset.ID)
		app.printAssetDetails(asset, len(techniques))
		viewed := false
		for {
			fmt.Fprintln(app.out, "\nNext:")
			if !viewed {
				fmt.Fprintln(app.out, "  [1] View mapped techniques")
			}
			fmt.Fprint(app.out, "  [b] Back to assets\n  [q] Return to guided menu\n> ")
			next, err := readLine(app.reader)
			if err != nil || strings.EqualFold(next, "q") {
				return
			}
			if strings.EqualFold(next, "b") {
				break
			}
			if next != "1" || viewed {
				app.printInvalidSelection()
				continue
			}
			app.printSubsection("Mapped Techniques")
			app.printTechniqueMapping("asset", techniques, false)
			viewed = true
		}
	}
}
