## MITRE ATT&CK CLI EXPLORER TOOL

CLI tool written in Go to explore MITRE ATT&CK techniques offline.
*This is an unofficial and **learning** project, not affiliated with MITRE.*

### DISCLAIMER
**THIS PROJECT USES MITRE ATT&CK DATA UNDER MITRE ATT&CK TERMS OF USE. MITRE ATT&CK AND ATT&CK ARE REGISTERED TRADEMARKS OF THE MITRE CORPORATION.**

## Description
A CLI for exploring MITRE ATT&CK data offline in a simple, learning-friendly workflow.
It supports quick lookup, guided navigation, and local cache-based querying without needing live web requests for every command.

## Current Features (v0.8)
- Offline cache + update pipeline.
- Mappings for groups, mitigations, software, campaigns, detections, analytics, and data components.
- Interactive guided/manual modes.
- Plain/detailed output modes.

### Core Commands

### Update local cache

```bash
go run . update
go run . update -f
```

Downloads and normalizes the ATT&CK dataset into the local cache.

### Search techniques

```bash
go run . search powershell
go run . search powershell --name-only
go run . search powershell --in-detection
```

Shows technique names/description, with optional detection-note searching.

### Show a technique

```bash
go run . show T1059
go run . show detection T1059
```

Shows technique details or detection notes for a technique.

### List targets

```bash
go run . list groups
go run . list detections
go run . list data-components
```

Lists supported targets with pagination.

### Explore entities

```bash
go run . group G0020
go run . group G0020 -t
go run . detection DET0505 -a -c
go run . analytic AN1394 -c
```

Shows entity details and optionally expands mapped relationships.

### Flags

```bash
-t, --techniques  Show mapped techniques
-a, --analytics   Show mapped analytics
-c, --components  Show mapped data components
-d, --detailed    Show detailed technique output
--plain           Disable colored output
-f, --force       Force dataset update
```

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
- `cmd_router.go`: central CLI command routing and global flag preprocessing.
- `cmd_update.go`: `update` command handler (download/meta/cache rebuild flow).
- `cmd_core.go`: core technique handlers (`search`, `show`, `list`).
- `cmd_map.go`: mapping handlers (`group`, `mitigation`, `software`, `campaign`, `detection`, `analytic`).
- `guided_mode.go`: guided explorer flow and guided-specific detail rendering.
- `data/mitre-cache.json`: normalized local cache used by `search`, `show`, and `list`.
- `data/enterprise-attack.json`: raw Enterprise ATT&CK dataset downloaded by `update`.
- `data/update-meta.json`: stores ETag/Last-Modified identifiers for update checks.

## Usage
```bash
go run . <command> [arguments] [options]
```

Common pattern:
```bash
go run . list <target>
go run . <entity> <id_or_name> [flags]
```
Available `list` targets: techniques, groups, mitigations, software, campaigns, detections, analytics, data-components, tactics, and platforms.

Entity commands: group, mitigation, software, campaign, detection, and analytic.

- `go run .` starts interactive mode

## Roadmap
- **v0.8.1**: add flag validation per entity command.
- **v0.8.2**: add dedicated `help` command + support global and target-specific help.
- **v0.8.3**: improve list/search discoverability.

## Notes
- ATT&CK Enterprise tactic model changed in ATT&CK v19 (April 2026):
  - `Defense Evasion` was split into `Stealth` and `Defense Impairment`.
- This project tracks current tactics in guided/list flows.
