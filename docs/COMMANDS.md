# Command Guide

This guide shows the most common ways to run MITRE Explorer. You can use commands directly or start guided mode if you prefer navigating step by step.

## Basic Pattern

```bash
go run . <command> [arguments] [options]
```

Think of it as: choose what you want to do, provide the target, then add optional flags.

```bash
go run .
```

Starts interactive guided mode, which lets you explore the cache without memorizing commands.

## Global Options

These options can be attached to most commands.

- `--matrix enterprise|mobile|ics`: selects which ATT&CK matrix the command should use. If omitted, Enterprise is used by default.
- `--plain`: disables colored output for terminals or environments where colors are not supported.

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

Shows cache health, matrix name, update metadata, parsed entity counts, and tactic validation.

Useful options:
- `--matrix enterprise|mobile|ics`: checks the status of a specific matrix cache.

## Techniques

Techniques are the main ATT&CK behaviors explored by the tool. You can search for them, inspect one directly, or list them using filters.

### Search

```bash
go run . search powershell
```

Searches technique names and descriptions by default.

Useful options:
- `--name-only`: searches only technique names.
- `--in-detection`: searches technique detection notes.
- `--limit <number>`: limits the number of returned results.
- `--target <target>`: searches another cached target, such as `groups`, `software`, `detections`, `analytics`, or `all`.
- `--matrix enterprise|mobile|ics`: searches a specific matrix cache.

### Show

```bash
go run . show T1059
```

Shows detailed information for one technique.

Useful options:
- `show detection <technique_id>`: shows only the detection notes for a technique.
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

## Entities and Mappings

Entities are ATT&CK objects that can be connected to techniques or other objects. The tool can show details for each entity and optionally expand mapped relationships.

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

Use `list` when you want to browse available cache objects without knowing a specific ID.

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

Useful options:
- `--matrix enterprise|mobile|ics`: lists targets from a specific matrix cache.
- `--plain`: disables colored output.

## Exports

Exports create simple CSV or Markdown reports from the local cache. Markdown reports include matrix and dataset metadata.

```bash
go run . export summary --format md --out reports/summary.md
```

Exports a summary report for the selected matrix.

Useful options:
- `--format csv|md`: selects CSV or Markdown output.
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

## Troubleshooting

If a cache is missing, update the selected matrix first:

```bash
go run . update --matrix ics
```

If a matrix name is not supported, the command will stop and show the supported options.

If colored output looks strange in your terminal, add `--plain`.
