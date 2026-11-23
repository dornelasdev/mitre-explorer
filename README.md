# MITRE ATT&CK Explorer CLI

A Go CLI for downloading, normalizing, and exploring MITRE ATT&CK data offline.

> This is an unofficial learning and portfolio project. It is not affiliated with
> or endorsed by The MITRE Corporation.

## What It Does

MITRE ATT&CK Explorer builds a local JSON cache from the official ATT&CK STIX
datasets. After an update, searches, mappings, guided navigation, and reports use
that local cache instead of making a web request for every query.

The tool supports the Enterprise, Mobile, and ICS matrices. Enterprise is selected
by default.

## Features

- Conditional dataset updates using ETag and Last-Modified metadata, plus offline
  cache rebuilds from an existing download.
- Offline technique and entity searches after the selected cache is built.
- Direct technique mappings in both directions, with ATT&CK procedure examples
  and their supplied citations.
- Connections between groups, software, and campaigns.
- Detection strategy, analytic, and data component relationships, with platforms,
  log-source channels, and tunable fields in analytic details.
- ICS asset details, sectors, related asset examples, and technique mappings.
- Warnings for detection references whose targets are unavailable in the selected
  matrix cache, including partial mappings.
- Guided explorer, manual command, and full-screen TUI modes with scoped search
  and in-session matrix selection.
- Matrix-aware, paginated, plain, and detailed terminal output.
- CSV and Markdown exports, including mapped relationship reports.
- Automated unit, integration, interactive, and multi-matrix regression tests.

## Quick Start

Use the Go version declared in [`go.mod`](go.mod). The full-screen interface uses
Bubble Tea, Bubbles, and Lip Gloss; `go mod download` fetches the declared
dependencies.

Build the default Enterprise cache:

```bash
go run . update
```

Search it or inspect a technique:

```bash
go run . search powershell
go run . show T1059 --detections
go run . group G0020 --techniques
```

Start the interactive menu:

```bash
go run .
```

Or browse ATT&CK objects and their relationships in the full-screen TUI:

```bash
go run . tui
```

Select another matrix with a global option:

```bash
go run . update --matrix mobile
go run . list tactics --matrix mobile
```

Mobile and ICS have independent raw datasets, caches, and update metadata. Run
`update --matrix <name>` before querying a matrix for the first time.

Already have the raw dataset? Rebuild its cache offline to populate fields added
since your last rebuild. For example, to load ICS assets:

```bash
go run . update --rebuild --matrix ics
go run . list assets --matrix ics
```

## Commands

| Command | Purpose |
| --- | --- |
| `update` | Refresh a matrix dataset or rebuild its cache offline. |
| `status` | Inspect cache metadata, object counts, tactics, and unresolved detection references. |
| `search` | Search techniques or another cached ATT&CK object type. |
| `show` | Display a technique, its detection notes, or its direct mappings and procedure examples. |
| `list` | Browse cache objects with pagination and optional technique filters. |
| `group`, `mitigation`, `software`, `campaign` | Show an object and optional mappings. |
| `detection`, `analytic` | Display detection content and linked objects. |
| `asset` | Show asset details and optional technique mappings (ICS only). |
| `export` | Write cache or relationship data as CSV or Markdown. |
| `tui` | Browse cached ATT&CK objects and relationships full-screen. |
| `help` | Show global or command-specific help. |

Global options:

```text
--matrix <enterprise|mobile|ics>  Select a matrix
--plain                           Disable colored output
```

See [docs/COMMANDS.md](docs/COMMANDS.md) for every target, flag, mapping export,
interactive behavior, and exit code.

## Interactive Mode

Running the tool without a command opens a menu:

- **Guided Explorer** navigates tactics and ATT&CK objects step by step.
- **Manual Command Mode** accepts the same commands without the `go run .` prefix.
- Matrix and plain-output selections persist within one interactive session.
- Quoted multiword values such as `"Process Creation"` are supported.
- Use `q` to quit and `back` or `b` where shown to return to a previous screen.

## Project Layout

```text
.
|-- .github/workflows/go.yml   # Formatting, test, and vet checks
|-- docs/
|   |-- COMMANDS.md            # Complete command reference
|   `-- DEVELOPMENT.md         # Architecture and development workflow
|-- internal/
|   |-- attack/                # ATT&CK models, STIX, storage, and queries
|   |-- cli/                   # Commands, session state, and line-oriented UI
|   |-- detailtext/            # Shared content for terminal detail views
|   `-- tui/                   # Full-screen Bubble Tea interface
|-- main.go                    # Thin executable entry point
`-- version.go                 # Build-overridable release version
```

Tests are colocated with the packages they cover. Small fixtures live under
`internal/attack/testdata/`.

## Local Data

Generated files are intentionally excluded from Git:

- `data/`: downloaded STIX bundles, normalized caches, and update metadata.
- `reports/`: default location for generated CSV and Markdown reports.
- `.gocache/`: optional repository-local Go build cache.

Do not commit downloaded ATT&CK datasets, generated reports, secrets, or local-only
coordination files.

## Development

Run the standard checks from the repository root:

```bash
gofmt -l .
go test ./...
go vet ./...
```

For architecture decisions, race checks, fixtures, and the branch/PR workflow, see
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Project Status

`v1.0` is the release baseline. Post-v1.0 development added the full-screen TUI,
expanded ATT&CK coverage, and handling for unresolved references found during the
v20.0 compatibility check. Older caches still load; an offline rebuild makes the
newly supported fields available.

## ATT&CK Data And Trademarks

This project uses publicly available MITRE ATT&CK data under the MITRE ATT&CK terms
of use. MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation.

The Enterprise tactic scheme represented by the tool includes `Stealth` and
`Defense Impairment`. The `status` command reports tactic names present in a cache
that are not yet recognized by the selected matrix configuration.
