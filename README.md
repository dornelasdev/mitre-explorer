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

## Current Features (v0.3)
- `search <term>`: returns matching techniques from local cache (offline).
- `show <technique_id>`: prints full details for a specific technique.
- Local JSON parsing and basic CLI command handling.
- `update`: downloads Enterprise ATT&CK STIX data, parses techniques, and builds local cache.
  - `update --force` or `update --f`: forces raw file re-download before rebuilding cache.
- `list --tactic <name>`: lists techniques by tactic.
- `list --platform <name>`: lists techniques by platform.


## Structure
- `main.go`: entry point of the program, command routing, parsing, and query logic.
- `data/techniques.json`: local sample dataset used in **v0.1**.
- `data/mitre-cache.json`: normalized local cache used by `search`, `show`, and `list`.
- `data/enterprise-attack.json`: raw Enterprise ATT&CK dataset downloaded by `update`.

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
- **v0.35**: improve search quality (sorting, name-priority matches, optional filters).
- **v0.4**: refactor `main.go` into multiple files/modules.
- **v0.5**: smarter update logic (skip unchanged remote data with metadata checks, keep `--force` override).
