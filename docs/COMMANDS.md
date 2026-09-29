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

Before searching or exploring a matrix, download and build its local cache.

```bash
go run . update
```

Downloads and normalizes the Enterprise matrix by default.

Useful options:
- `-f`, `--force`: forces a fresh download and cache rebuild.
- `--matrix enterprise|mobile|ics`: updates a specific matrix cache.

```bash
go run . status
```

Shows cache health, matrix name, update metadata, parsed entity counts, and tactic
validation. A missing cache is reported as status information rather than a command
failure.

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
- `--target <target>`: searches another cached object type or `all`.

Search targets are `groups`, `mitigations`, `software`, `campaigns`, `detections`,
`analytics`, `data-components`, and `all`.
- `--detailed`: shows detailed technique results.
- `--matrix enterprise|mobile|ics`: searches a specific matrix cache.

`--name-only`, `--in-detection`, and `--detailed` apply only to technique searches.

### Show

```bash
go run . show T1059
```

Shows detailed information for one technique.

Alternative form:

- `show detection <technique_id>`: shows the technique ID, name, and detection notes.

Global option:

- `--matrix enterprise|mobile|ics`: shows the technique from a specific matrix cache.

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

### Groups

```bash
go run . group G0020
```

Shows details for a group, intrusion set, or actor-like object in the cache.

Useful options:
- `-t`, `--techniques`: shows techniques mapped to the group.
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
- `-d`, `--detailed`: shows detailed technique output when used with `-t`.
- `--matrix enterprise|mobile|ics`: queries a specific matrix cache.

### Campaigns

```bash
go run . campaign C0010
```

Shows details for a campaign when campaign data is available in the selected matrix.

Useful options:
- `-t`, `--techniques`: shows techniques mapped to the campaign.
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

Shows details for an analytic.

Useful options:
- `-c`, `--components`: shows data components used by the analytic.
- `--matrix enterprise|mobile|ics`: queries a specific matrix cache.

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
- `tactics`: lists tactics in matrix-specific order.
- `platforms`: lists platforms found in the selected matrix cache.

Only `list techniques` accepts `--tactic`, `--platform`, and `--data-component`
filters. Other list targets reject filters.

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

Use these targets when exporting mapped relationships:

- `group-techniques`: exports techniques mapped to a group.
- `mitigation-techniques`: exports techniques mapped to a mitigation.
- `software-techniques`: exports techniques mapped to software.
- `campaign-techniques`: exports techniques mapped to a campaign.
- `detection-techniques`: exports techniques mapped to a detection strategy.
- `detection-analytics`: exports analytics mapped to a detection strategy.
- `detection-components`: exports data components connected to a detection strategy.
- `analytic-components`: exports data components mapped to an analytic.

Mapped relationship exports also need:

- `--for <id_or_name>`: selects the source object for the mapping.

Example:

```bash
go run . export group-techniques --for G0020 --format md --out reports/group-techniques.md
```

Exports techniques mapped to the selected group.

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

## Full-Screen TUI

Open the full-screen interface with:

```bash
go run . tui
```

The TUI loads the selected local cache and provides a responsive path from ordered
tactics to their techniques and technique details. Move with the arrow keys or
`j`/`k`, open an item with `Enter`, and return one level with `b` or `Esc`. At the
tactic root, `Esc` exits. The existing CLI and guided mode remain fully available.

The global `--matrix` and `--plain` options are supported:

```bash
go run . tui --matrix mobile --plain
```

Use `q` or `Ctrl+C` to leave the TUI from any screen. If the selected cache is
missing, the TUI shows the corresponding matrix update command.

## Troubleshooting

If a cache is missing, update the selected matrix first:

```bash
go run . update --matrix ics
```

If a matrix name is not supported, the command will stop and show the supported options.

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
rather than silently ignored; filters are supported only by `list techniques`.
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
