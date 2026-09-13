# Development

This project started as a Go learning project. After v1.0, the rework focuses on
clearer responsibilities, automated checks, and changes that are easy to review.

## Setup

Use the Go version declared in `go.mod`. Run the commands below from the repository
root. The project currently uses the Go standard library, so no additional library
installation is needed.

```bash
go run . help
```

For command usage and matrix options, see [COMMANDS.md](COMMANDS.md).

## Development Checks

Format the Go files you changed. For example:

```bash
gofmt -w main.go interactive_mode.go ui.go
```

Then run the automated checks:

```bash
go test ./...
go vet ./...
```

Tests use small fixtures and do not require downloaded ATT&CK datasets. They cover
query behavior, matrix selection, export helpers, version availability, closed
input handling, conditional downloads, storage, and STIX normalization. HTTP tests
use local fixture servers rather than requesting live ATT&CK data. The interactive
EOF tests use separate processes with a timeout
so a loop regression cannot hang the suite indefinitely.

`go vet` checks for suspicious Go code. Passing these checks helps catch
regressions, but manual checks are still useful for terminal layout, colors,
navigation, and flows involving real caches.

To check formatting without changing files, and check the Git diff for whitespace
errors:

```bash
gofmt -l .
git diff --check
```

`gofmt -l .` should print no filenames.

## Continuous Integration

The [Go workflow](../.github/workflows/go.yml) runs on pushes and pull requests.
It uses the Go version from `go.mod` and checks formatting, runs the tests, and
runs `go vet`. A formatting failure means files need to be formatted locally and
included in the next commit.

## Local Data

The `update` command creates the local data directory when needed. Raw datasets,
normalized caches, and update metadata live under `data/`; the generated files
for Enterprise, Mobile, and ICS are ignored by Git. Reports written under
`reports/`, the local `.gocache/` directory, and `.DS_Store` files are also ignored.

Keep test fixtures small and separate from downloaded datasets. Do not commit
generated caches or reports. If exporting to a different directory, check
`git status` before staging because that directory may not be ignored.

## Rework Workflow

Work through a coherent implementation section, review the diff, run the relevant
checks, and manually verify any affected interactive flows. Create commits at
meaningful checkpoints; a commit is not required for every section.

```bash
git status --short --branch
git diff
git diff --cached
```

Review staged changes as well as unstaged changes. Push the rework branch when it
is ready for a pull request, then review and merge that pull request.

## Data Layer

`internal/attack` owns shared entity models, downloading, STIX normalization, and
cache/metadata storage. The CLI imports it as `mitre-explorer/internal/attack`.
Exported names such as `attack.CacheData` and `attack.LoadCacheData` identify the
package boundary; STIX decoding types and implementation helpers remain private.

Matrix selection and terminal rendering stay in the CLI. Data-layer functions
receive explicit paths and return values or errors without printing. This lets
tests use temporary directories and small fixtures instead of application data.

### Update Pipeline Rework

- Moved the former `types.go` and `update.go` responsibilities into `models.go`,
  `download.go`, `stix.go`, and `cache.go` inside `internal/attack`.
- Kept command syntax, generated dataset/cache paths, JSON field names, and
  normalization rules compatible with existing caches.
- Removed the unused mock-era `buildTechniquesFromSTIX`, `saveTechniques`, and
  `loadTechniques` helpers. The normalized multi-entity cache is the active path.
- Downloads now have a five-minute timeout covering the request and body transfer.
  A timeout reports an update failure rather than waiting indefinitely.
- Downloads, caches, and metadata are written to a temporary file in the
  destination directory, closed successfully, then renamed into place. A failed
  transfer or write preserves the previous file and cleans up its temporary file.
  Each file is replaced independently; this is not a transaction across all three.
- Directory creation uses the supplied path's parent rather than a hardcoded
  `data/` directory.
- A new HTTP 200 response uses its own ETag and Last-Modified values. Missing
  validators are cleared instead of retaining identifiers from the older file;
  an HTTP 304 response continues retaining the previous validators.
- Shared JSON storage helpers remove duplicate loading/saving code. This section
  makes no runtime speedup claim; JSON decoding still loads the bundle in memory.

Regression tests cover existing cache fields, entity filtering, relationship
resolution, detection enrichment, ID fallbacks, conditional/forced requests,
incomplete HTTP responses, and preservation of existing files after write errors.
