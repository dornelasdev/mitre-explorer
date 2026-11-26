# Command Reference

This guide documents the supported commands, targets, options, interactive
behavior, and exit codes for MITRE ATT&CK Explorer.

## Basic Pattern

```bash
go run . <command> [arguments] [options]
```

The examples use `go run .`. After building the tool, replace that prefix with
the binary path:

```bash
go build -o mitre-explorer .
./mitre-explorer search powershell
```

```bash
go run .
```

Starts the interactive menu, where you can choose guided exploration or manual command input.

## Global Options

These options can be attached to any command and may appear before or after
command-specific arguments.

- `--matrix enterprise|mobile|ics`: selects the ATT&CK matrix. Enterprise is the default.
- `--plain`: disables colored output.

Each standalone run defaults to Enterprise with colors enabled. In manual mode,
`--matrix` and `--plain` apply to the current session: later commands keep those
settings when the flags are omitted. Returning to the mode menu also keeps the
selected matrix and color setting. Invalid matrix options show an error and leave
the current settings unchanged. Quote multiword values in manual mode just as you
would in a standalone shell command, for example
`--data-component "Process Creation"`. Multiword standalone arguments must also
be quoted so the shell passes them as one value.

## Cache Management

Before searching or exploring a matrix, build its local cache.

```bash
go run . update
```

Downloads and normalizes the Enterprise matrix by default. A normal update can
skip the download and leave the cache unchanged when the remote dataset has not
changed.

Useful options:

- `-f`, `--force`: forces a fresh download and cache rebuild.
- `--rebuild`: rebuilds from the local raw dataset without a download or a change
  to update metadata. Cannot be combined with `--force`.
- `--matrix enterprise|mobile|ics`: updates a specific matrix cache.

If an older cache is missing procedure citations, enriched analytic fields, or
ICS assets, rebuild the affected matrix from its existing dataset:

```bash
go run . update --rebuild --matrix ics
```

If you do not have the raw dataset yet, run a normal update for that matrix first.

```bash
go run . status
```

Shows cache health, matrix name, update metadata, parsed entity counts, tactic
validation, and unresolved detection references. These checks cover detection
strategy-to-analytic and analytic-to-data-component references. A missing cache is
reported as status information rather than a command failure.

Useful options:
- `--matrix enterprise|mobile|ics`: checks the status of a specific matrix cache.

## Techniques

Techniques are the main ATT&CK behaviors explored by the tool. You can search for
them, inspect one directly, or list them using filters.

### Search

```bash
go run . search powershell
```

Searches technique names and descriptions by default.

Useful options:

- `--name-only`: searches only technique names.
- `--in-detection`: searches technique detection notes instead of names and descriptions.
- `--limit <number>`: limits the number of returned results.
- `--target <target>`: selects a search scope.
- `--detailed`: shows detailed technique results.
- `--matrix enterprise|mobile|ics`: searches a specific matrix cache.

Targets include `techniques`, `groups`, `mitigations`, `software`, `campaigns`,
`detections`, `analytics`, `data-components`, and `assets` (ICS only).
`--target all` searches non-technique entities in the selected cache.
`--name-only`, `--in-detection`, and `--detailed` apply only to technique searches.

### Show

```bash
go run . show T1059
```

Shows detailed information for one technique. Add mapping flags to explore its
direct relationships, for example `show T1059 --mitigations --detections`.

- `--groups`, `--software`, `--campaigns`, `--mitigations`, and `--detections`:
  expand the corresponding mapped objects.
- `--procedures`: shows descriptions of recorded uses by groups, software, and
  campaigns, with citations supplied by ATT&CK when available.
- `--assets`: shows directly mapped assets (ICS only).
- `--all`: includes every mapping supported by the selected matrix.

Flags can be combined. Mappings apply to the exact technique or sub-technique ID;
they are not inherited between a parent technique and its sub-techniques.
`show detection <technique_id>` shows only the ID, name, and detection notes. It
does not accept these mapping flags.

### List

```bash
go run . list techniques
```

Lists techniques from the selected matrix.

Useful filters:
- `--tactic <name>`: lists techniques by tactic.
- `--platform <name>`: lists techniques by platform.
- `--data-component <name>`: lists techniques by data component.
- `--matrix enterprise|mobile|ics`: lists techniques from a specific matrix cache.

## Entities And Mappings

Entities are ATT&CK objects that can be connected to techniques or other objects.
The tool can show details for each entity and optionally expand mapped relationships.
Group, software, and campaign connections follow direct relationships in the
selected cache. Shared techniques do not imply that two objects are connected;
in particular, campaign attribution is not inferred from shared software.

### Groups

```bash
go run . group G0020
```

Shows details for a group, intrusion set, or actor-like object in the cache.

Useful options:
- `-t`, `--techniques`: shows techniques mapped to the group.
- `--software`: shows software linked directly to the group.
- `--campaigns`: shows campaigns attributed to the group.
- `-d`, `--detailed`: shows detailed technique output when used with `-t`.
- `--matrix enterprise|mobile|ics`: queries a specific matrix cache.

### Mitigations

```bash
go run . mitigation M1036
```

Shows details for a mitigation.

Useful options:
- `-t`, `--techniques`: shows techniques addressed by the mitigation.
- `-d`, `--detailed`: shows detailed technique output when used with `-t`.
- `--matrix enterprise|mobile|ics`: queries a specific matrix cache.

### Software

```bash
go run . software S0002
```

Shows details for software, malware, or tools represented in ATT&CK.

Useful options:
- `-t`, `--techniques`: shows techniques mapped to the software.
- `--groups` and `--campaigns`: show groups and campaigns directly linked to the software.
- `-d`, `--detailed`: shows detailed technique output when used with `-t`.
- `--matrix enterprise|mobile|ics`: queries a specific matrix cache.

### Campaigns

```bash
go run . campaign C0010
```

Shows details for a campaign when campaign data is available in the selected matrix.

Useful options:
- `-t`, `--techniques`: shows techniques mapped to the campaign.
- `--software`: shows software linked directly to the campaign.
- `--groups`: shows groups to which the campaign is attributed.
- `-d`, `--detailed`: shows detailed technique output when used with `-t`.
- `--matrix enterprise|mobile|ics`: queries a specific matrix cache.

### Detection Strategies

```bash
go run . detection DET0505
```

Shows details for a detection strategy.

Useful options:
- `-t`, `--techniques`: shows techniques mapped to the detection strategy.
- `-a`, `--analytics`: shows analytics mapped to the detection strategy.
- `-c`, `--components`: shows data components connected through mapped analytics.
- `-d`, `--detailed`: shows detailed technique output when used with `-t`.
- `--matrix enterprise|mobile|ics`: queries a specific matrix cache.

### Analytics

```bash
go run . analytic AN1394
```

Shows details for an analytic, including platforms, log-source names and channels,
and mutable elements (tunable fields described by ATT&CK), when the cache has them.

Detection and analytic details warn when referenced analytics or data components
are unavailable in the selected matrix cache. Available results remain visible;
incomplete counts are marked as resolved. An unresolved reference differs from
an object having no mapped items. The tool does not automatically fetch another
matrix to fill missing references.

Useful options:
- `-c`, `--components`: shows data components used by the analytic.
- `--matrix enterprise|mobile|ics`: queries a specific matrix cache.

### ICS Assets

```bash
go run . asset A0011 --matrix ics
```

Shows an asset's description, platforms, sectors, and related asset examples.
Use an ATT&CK ID, STIX ID, or exact name. Add `-t` or `--techniques` to list directly
mapped techniques; add `-d` or `--detailed` for detailed technique output (requires
`-t` or `--techniques`).

Use `list assets --matrix ics` to browse assets or
`search <term> --target assets --matrix ics` to find one. Start from a technique
with `show <technique_id> --assets --matrix ics` to explore the reverse mapping.
Related asset examples are descriptions, not additional technique mappings.

Filter the asset list by sector, platform, or both:

```bash
go run . list assets --matrix ics --sector "Water and Wastewater" --platform Embedded
```

Both filters match complete names, ignoring case and surrounding whitespace.
When combined, both must match the asset's own metadata. A sector mentioned only
in a related asset example does not count.

## Lists

Use `list` to browse available cache objects without knowing a specific ID.

```bash
go run . list groups
```

Lists groups from the selected matrix cache with pagination.

Available targets:
- `techniques`: lists techniques.
- `groups`: lists groups.
- `mitigations`: lists mitigations.
- `software`: lists software, malware, and tools.
- `campaigns`: lists campaigns.
- `detections`: lists detection strategies.
- `analytics`: lists analytics.
- `data-components`: lists data components.
- `assets`: lists assets (ICS only).
- `tactics`: lists tactics in matrix-specific order.
- `platforms`: lists platforms found in the selected matrix cache.

`list techniques` accepts `--tactic`, `--platform`, and `--data-component`.
`list assets` accepts `--sector` and `--platform` on ICS. Other list targets
reject filters.

Global options:
- `--matrix enterprise|mobile|ics`: lists targets from a specific matrix cache.
- `--plain`: disables colored output.

## Exports

Exports create CSV or Markdown reports from the local cache. Markdown reports
include matrix and dataset metadata. `--out` is required; `--format` defaults to
`csv`.

```bash
go run . export summary --format md --out reports/summary.md
```

Exports a summary report for the selected matrix.

Useful options:
- `--format csv|md`: selects CSV or Markdown output; CSV is the default.
- `--out <file>`: sets the output file path.
- `--matrix enterprise|mobile|ics`: exports data from a specific matrix cache.

### Export Targets

Use these targets when exporting cache data directly:

- `summary`: exports cache metadata and entity counts.
- `techniques`: exports techniques.
- `groups`: exports groups.
- `mitigations`: exports mitigations.
- `software`: exports software.
- `campaigns`: exports campaigns.
- `detections`: exports detection strategies.
- `analytics`: exports analytics.
- `data-components`: exports data components.
- `assets`: exports ICS asset details, including platforms, sectors, and related
  asset examples. Requires `--matrix ics`.

Use these targets when exporting mapped relationships:

- `group-techniques`: exports techniques mapped to a group.
- `mitigation-techniques`: exports techniques mapped to a mitigation.
- `software-techniques`: exports techniques mapped to software.
- `campaign-techniques`: exports techniques mapped to a campaign.
- `detection-techniques`: exports techniques mapped to a detection strategy.
- `detection-analytics`: exports analytics mapped to a detection strategy.
- `detection-components`: exports data components connected to a detection strategy.
- `analytic-components`: exports data components mapped to an analytic.
- `technique-procedures`: exports procedure text and supplied citations for one
  exact technique or sub-technique.
- `asset-techniques` and `technique-assets`: export direct mappings between ICS
  assets and techniques. Both require `--matrix ics`.
- `group-software` and `software-groups`: export direct links between groups and software.
- `campaign-software` and `software-campaigns`: export direct links between campaigns and software.
- `campaign-groups` and `group-campaigns`: export direct campaign attribution.

Mapped relationship exports also need:

- `--for <id_or_name>`: selects the starting object, as named before the first
  hyphen in the target. For `technique-procedures` and `technique-assets`, supply
  the technique ID. Do not use `--for` for ordinary lists such as `assets`.

Example:

```bash
go run . export group-techniques --for G0020 --format md --out reports/group-techniques.md
```

Exports techniques mapped to the selected group.

For example, export the ICS asset inventory or procedure citations for a technique:

```bash
go run . export assets --matrix ics --out reports/ics-assets.csv
go run . export technique-procedures --for T1059 --format md --out reports/procedures.md
```

Procedure exports have one row per supplied citation. An uncited procedure appears
once with blank citation columns. The exported row count can therefore exceed the
number of procedure examples. If an older cache lacks these fields, use
[`update --rebuild`](#cache-management) with the affected matrix.

## Matrix Examples

Enterprise is the default matrix, so these two commands use the same cache:

```bash
go run . search powershell
go run . search powershell --matrix enterprise
```

Mobile and ICS can be selected explicitly:

```bash
go run . list tactics --matrix mobile
go run . list tactics --matrix ics
```

Use `update` before querying a matrix for the first time:

```bash
go run . update --matrix mobile
go run . update --matrix ics
```

## Interactive Sessions

Running `go run .` opens guided and manual modes. Manual commands omit the
`go run .` prefix, accept quoted values and backslash escapes, and use one shared
input stream across menus and pagination. They do not perform shell expansion or
execute nested shell commands.

A failed manual command prints its diagnostic and returns to the `manual>` prompt.
Matrix and `--plain` selections persist until the process exits.

In the guided explorer, select a technique to see its mapping menu, including
procedure examples, or select a group, software item, or campaign to see its
connections. Start with `go run . --matrix ics`, then choose **Guided Explorer**
and **Explore Assets** to browse asset details and mapped techniques.

## Full-Screen TUI

Open the full-screen interface with:

```bash
go run . tui
```

The TUI loads the selected local cache and opens an Explore menu for tactics,
groups, mitigations, software, campaigns, detection strategies, analytics, and
data components. With ICS selected, the Explore menu and search scopes also
include assets. Open an object's details and press `Enter` to follow its mappings.
Techniques expose reverse mappings and procedure examples; in ICS you can move
from an asset to a mapped technique and back to the technique's linked assets.
On the main **Assets** list, press `f` to open its filters. Use `Tab` to switch
between sector and platform, Left/Right to choose a cached value (or **Any**),
`Enter` to apply, and `Esc` to cancel. Active filters appear above the results.
Press `c` on the list to clear both. Filters stay applied when you open an asset
and go back, but do not change search results or mapping pages.

Move through lists and scroll long details with the arrow keys or `j`/`k`, open an
item with `Enter`, and return one level with `b` or `Esc`. At the Explore root,
`Esc` exits.

Press `/` from an explorer page to search the local cache. `Tab` and `Shift+Tab`
cycle through the `All` scope (including techniques) or a specific object type.
Results update while typing. `Enter` opens the result list and `Esc` cancels
without changing the current page.
Search results retain the same detail and mapping navigation as ordinary lists.

Press `m` to select an existing Enterprise, Mobile, or ICS cache without leaving
the TUI. Switching matrices does not download data. If the selected cache is
missing, the TUI shows its update command and keeps the previous session available.
Press `?` for contextual keyboard help. Breadcrumbs show the current path, while
lists and scrollable details display their current positions.

The global `--matrix` and `--plain` options are supported:

```bash
go run . tui --matrix mobile --plain
```

Use `q` to leave the explorer or `Ctrl+C` to exit from any screen.

## Troubleshooting

If a cache is missing, update the selected matrix first:

```bash
go run . update --matrix ics
```

If a matrix name is not supported, the command will stop and show the supported options.

If your ICS cache loads but has no assets, use the
[offline rebuild](#cache-management) command rather than forcing a download.

If colored output looks strange in your terminal, add `--plain`.

## Errors And Exit Codes

Standalone commands write failure diagnostics to stderr and return:
- `0`: success, including empty search/mapping results. `status` also treats a
  missing cache as informational.
- `1`: an operation failed, such as loading a cache, finding a requested entity,
  downloading data, or writing a report.
- `2`: invalid command usage, such as an unknown command/option, a missing value,
  or unsupported flag combinations.

Arguments and flags are validated before cache access. Extra arguments are rejected
rather than silently ignored; list filters are supported only by
`list techniques` and `list assets`.
Export `--for` is required for mapped relationship targets and rejected for ordinary
entity/summary exports. Option values must be nonempty and cannot be another flag.

Manual mode reports command failures without closing the session. A later successful
command is unaffected by the previous error. `--plain` also disables colors in
global-option errors without applying rejected settings to the session.

A corrupt metadata file is an error, not silently omitted from status or reports.
If an update saves its cache but cannot save metadata, the error explains that
partial success and returns `1`.

When using `go run .`, Go itself usually returns shell status `1` for a program
failure and prints `exit status 2` when the program returned `2`. A built binary
returns the tool's exit code directly.
