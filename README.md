## MITRE ATT&CK CLI EXPLORER TOOL

CLI tool written in Go to explore MITRE ATT&CK techniques offline.
*This is an unofficial and **learning** project, not affiliated with MITRE.*

### DISCLAIMER
**THIS PROJECT USES MITRE ATT&CK DATA UNDER MITRE ATT&CK TERMS OF USE. MITRE ATT&CK AND ATT&CK ARE REGISTERED TRADEMARKS OF THE MITRE CORPORATION.**

## Description
A CLI for exploring MITRE ATT&CK data offline in a simple, learning-friendly workflow.
It supports quick lookup, guided navigation, and local cache-based querying without needing live web requests for every command.

## Current Features (v0.7)
- Offline cache + update pipeline.
- Technique search/show/list.
- Group/mitigation mappings.
- Interactive guided/manual modes.
- Plain/detailed output modes.

### Core Commands
- `update`
  - Refresh local ATT&CK data and build cache.
  - Options: `-f` or `--force` (force re-download).

- `search <term>`
  - Search techniques in local cache.
  - Options: `--name-only`, `--limit N`.

- `show <technique_id>`
  - Show full details for one technique.

- `list`
  - `--tactic <name>`
  - `--platform <name>`

- `group techniques <group_id_or_name>`
  - List techniques mapped to a group.

- `group show <group_id_or_name>`
  - Show group details (aliases, description, etc.)

- `mitigation techniques <mitigation_id_or_name>`
  - List techniques mapped to a mitigation.

### Interactive Mode
- Launches when running `go run .` with no command arguments.
- **GUIDED EXPLORER**: navigate tactic -> technique -> details with in-terminal prompts.
- **MANUAL COMMAND MODE**: type commands directly inside the app.
- Navigation shortcuts: `q` to quit, `back`/`b` where applicable.

## Structure
- `main.go`: entry point of the program and command routing.
- `types.go`: core data models (STIX bundle/object structs, cache path constant).
- `update.go`: update pipeline (download raw ATT&CK data, parse STIX, build/write and load cache).
- `query.go`: search and filter logic.
- `ui.go`: terminal UX (spinner and human-readable size formatting), color/theme, and table/truncation helpers.
- `data/mitre-cache.json`: normalized local cache used by `search`, `show`, and `list`.
- `data/enterprise-attack.json`: raw Enterprise ATT&CK dataset downloaded by `update`.
- `data/update-meta.json`: stores ETag/Last-Modified identifiers for update checks.

## Usage
```bash
go run . update [-f | --force]
go run . search <term> [--name-only] [--limit N] [--detailed] [--plain]
go run . show <technique_id>
go run . list --tactic <name>
go run . list --platform <name>
go run . group techniques <group_id_or_name>
go run . mitigation techniques <mitigation_id_or_name>
```

- `go run .` starts interactive mode

## Notes
- ATT&CK Enterprise tactic model changed in ATT&CK v19 (April 2026):
  - `Defense Evasion` was split into `Stealth` and `Defense Impairment`.
- This project tracks current tactics in guided/list flows.
