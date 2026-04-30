## MITRE ATT&CK CLI EXPLORER TOOL

CLI tool written in Go to explore MITRE ATT&CK techniques offline.
*This is an unofficial and **learning** project, not affiliated with MITRE.*

### DISCLAIMER
**THIS PROJECT USES MITRE ATT&CK DATA UNDER MITRE ATT&CK TERMS OF USE. MITRE ATT&CK AND ATT&CK ARE REGISTERED TRADEMARKS OF THE MITRE CORPORATION.**

## Description
The main goal is to provide a simple command-line workflow to:
- Search techniques by keyword.
- Show technique details by ID.
- Work offline using locally stored data.

## Current Features (v0.6)

### Core Commands
- `search <term>`: returns matching techniques from local cache (offline).
- `show <technique_id>`: prints full details for a specific technique.
- Local JSON parsing and basic CLI command handling.
- `update`: downloads Enterprise ATT&CK STIX data, parses techniques, and builds local cache.
  - `update --force` or `update -f`: forces raw file re-download before rebuilding cache.
- `list --tactic <name>`: lists techniques by tactic.
- `list --platform <name>`: lists techniques by platform.

### Interactive Mode
- Launches wheh running `go run .` with no command arguments.
- **GUIDED EXPLORER**: navigate tactic -> technique -> details with in-terminal prompts.
- **MANUAL COMMAND MODE**: type commands directly inside the app.
- Navigation shortcuts: `q` to quit, `back`/`b` where applicable.

## Structure
- `main.go`: entry point of the program and command routing.
- `types.go`: core data models (STIX bundle/object structs, cache path constant).
- `update.go`: update pipeline (download raw ATT&CK data, parse STIX, build/write and load cache).
- `query.go`: search and filter logic.
- `ui.go`: terminal UX helpers (spinner and human-readable size formatting).
- `data/mitre-cache.json`: normalized local cache used by `search`, `show`, and `list`.
- `data/enterprise-attack.json`: raw Enterprise ATT&CK dataset downloaded by `update`.
- `data/update-meta.json`: stores ETag/Last-Modified identifiers for update checks.

## Usage
```bash
go run . update
go run . update -f
go run . search <term>
go run . show <technique_id>
go run . list --tactic <name>
go run . list --platform <name>
```

## Roadmap
- **v0.65**: improve output UX/UI (colors, compact/detailed modes, optional table formatting, clearer error/help messages, and more).
- **v0.7**: add ATT&CK entity expansion (APT groups via `intrusion-set` + group-to-technique mapping commands).
- **v0.8**: add export/report features (--json / --md) for search/list/show results.
