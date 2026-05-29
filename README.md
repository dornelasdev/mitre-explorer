## MITRE ATT&CK CLI EXPLORER TOOL

CLI tool written in Go to explore MITRE ATT&CK techniques offline.
*This is an unofficial and **learning** project, not affiliated with MITRE.*

### DISCLAIMER
**THIS PROJECT USES MITRE ATT&CK DATA UNDER MITRE ATT&CK TERMS OF USE. MITRE ATT&CK AND ATT&CK ARE REGISTERED TRADEMARKS OF THE MITRE CORPORATION.**

## Description
A CLI for exploring MITRE ATT&CK data offline in a simple, learning-friendly workflow.
It supports quick lookup, guided navigation, and local cache-based querying without needing live web requests for every command.

## Current Features (v0.7.6)
- Offline cache + update pipeline.
- Technique search/show/list.
- Group/mitigation/software/campaign mappings.
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

- `software techniques <software_id_or_name>`
  - List techniques mapped to that software.

- `software show <software_id_or_name>`
  - Show software details.

- `campaign show <campaign_id_or_name>`
  - Show campaign details.

- `campaign techniques <campaign_id_or_name>`
  - List techniques mapped to that campaign.

### Interactive Mode
- Launches when running `go run .` with no command arguments.
- **GUIDED EXPLORER**: navigate tactic -> technique -> details with in-terminal prompts.
- **MANUAL COMMAND MODE**: type commands directly inside the app.
- Navigation shortcuts: `q` to quit, `back`/`b` where applicable.

## Structure
- `main.go`: app entrypoint, interactive mode bootstrap, shared line-reader/output helper.
- `types.go`: core data models (STIX bundle/object structs, cache path constant).
- `update.go`: update pipeline (download raw ATT&CK data, parse STIX, build/write and load cache).
- `query.go`: search and filter logic.
- `ui.go`: terminal UX (spinner and human-readable size formatting), color/theme, and table/truncation helpers.
- `cmd_router.go`: central CLI comamnd routing and global flag preprocessing.
- `cmd_update.go`: `update` command handler (download/meta/cache rebuild flow).
- `cmd_core.go`: core technique handlers (`search`, `show`, `list`).
- `cmd_map.go`: mapping handlers (`group`, `mitigation`, `software`, `campaign`).
- `guided_mode.go`: guided explorer flow and guided-specific detail rendering.
- `data/mitre-cache.json`: normalized local cache used by `search`, `show`, and `list`.
  - `group/mitigation/software/campaign`
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

- See Core Commands above for complete command variants (group/software/campaign show + techniques).

- `go run .` starts interactive mode

## Roadmap
- **v0.7.6**: add matrix support groundwork (structure ready for mobile/ICS).
- **v0.7.7**: add campaign branch polish in guided mode.
- **v0.7.8**: add export flags for results.
- **v0.7.9**: pre-v0.8 cleanup pass.


## Notes
- ATT&CK Enterprise tactic model changed in ATT&CK v19 (April 2026):
  - `Defense Evasion` was split into `Stealth` and `Defense Impairment`.
- This project tracks current tactics in guided/list flows.
