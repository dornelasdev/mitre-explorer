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
gofmt -w main.go internal/cli/interactive_mode.go internal/cli/ui.go
```

Then run the automated checks:

```bash
go test ./...
go vet ./...
```

Use the race detector when changing shared session state, terminal concurrency,
or test helpers that run concurrently:

```bash
go test -race ./...
```

Tests use small fixtures and do not require downloaded ATT&CK datasets. They cover
query behavior, matrix selection, export helpers, version availability, closed
input handling, conditional downloads, storage, and STIX normalization. HTTP tests
use local fixture servers rather than requesting live ATT&CK data. The interactive
EOF and guided-flow tests use separate processes with timeouts so a loop regression
cannot hang the suite indefinitely.

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

## Change Workflow

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

## Package Layout

```text
.
|-- main.go                    # Process entry point only
|-- version.go                 # Build-overridable version
`-- internal/
    |-- attack/                # Models, STIX, storage, and query rules
    `-- cli/                   # Commands, session state, and terminal output
```

The root remains a small `main` package so `go run .` and existing build commands
continue to work. `internal/attack` contains terminal-independent data logic;
`internal/cli` owns command parsing, orchestration, and presentation. Go's
`internal` rule keeps both packages private to this module rather than presenting
them as a public library API.

## Data Layer

`internal/attack` owns shared entity models, downloading, STIX normalization,
cache/metadata storage, and query logic. The CLI imports it as
`mitre-explorer/internal/attack`.
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

### Query Rework

- Moved the root `query.go` and the entity-search logic from `cmd_core.go` into
  `search.go`, `query.go`, `relationships.go`, and `tactics.go` in `internal/attack`.
  CLI handlers, guided mode, and reports now use the same exported queries.
- Tactic collection and validation receive the selected matrix's tactic order
  explicitly. The data package does not read global CLI matrix state.
- Group, mitigation, software, campaign, and detection technique mappings share
  one relationship lookup. It filters relationship/source/target types, ignores
  unresolved targets, removes duplicate references, and sorts techniques by ID.
- Technique search still prioritizes names over descriptions, then sorts by ID.
  It normalizes the term once and skips description matching when a name matches
  or name-only mode is requested. Detection search retains its separate behavior.
- Entity search retains type/name ordering and adds an ID tie-breaker for equal
  names. The `all` entity target continues excluding techniques.
- Detection-to-component queries build one component index per query and resolve
  references directly across the linked analytics. They no longer rebuild that
  index and look up each analytic again inside the loop. No measured speedup is
  claimed, and these indexes are not retained across commands.
- Deduplication uses the external ID when a record lacks a STIX ID, preventing
  distinct analytics/components from collapsing into one empty-key result. Empty
  reference keys are excluded. Components sort by name, then ID for tied names.
- `FilterTechniques` applies the component query, then intersects tactic and
  platform filters. Previously a component filter discarded earlier filters in
  `list techniques`. All supplied filters now apply together, irrespective of
  their argument order. Component ID queries also trim surrounding whitespace.
- Kept the legacy component/source-text fallback when no component relationships
  resolve to techniques. Removed the unused `listByDataComponent` helper.

Tests cover search ranking/limits, explicit tactic ordering for all three matrices,
combined filters through both the query API and CLI handler, missing/duplicate
references, legacy fallbacks, and analytics/components without STIX IDs.

## Terminal Application

`internal/cli` owns command routing/handlers, matrix configuration, terminal
rendering, and guided/manual interaction. Its `Run(args, version)` entrypoint is
called by the root `main.go` and creates an `App` using the process streams.
Tests can call `New(input, output)` with supplied streams or use
`NewWithStreams(input, output, diagnostics)` when stdout/stderr separation matters.
The CLI imports `internal/attack` for data operations. The executable package
retains `version.go` and its version test.

### CLI Package Rework

- Moved terminal application files and their tests from the root into
  `internal/cli`, preserving their responsibilities and filenames.
- Replaced `runApp(args)` with `cli.Run(args, version)`. The executable supplies
  the version used in the banner, so build-time overrides such as
  `-ldflags "-X main.version=v1.0"` continue working.
- Kept valid command syntax, interactive prompts/navigation, and paths unchanged.
  Dataset/cache/report paths remain relative to the process working directory,
  not to the package source directory. Run the existing `go run .` and build
  commands from the repository root.
- Moved CLI tests with their implementation. `go test ./...` discovers the
  executable, data-layer, and CLI package tests.
- Runtime matrix/color state and input/output are owned by an `App` instance,
  following the session-state rework below.

### Session State And Streams

- `App` owns the selected matrix (including cache/metadata paths), color setting,
  one buffered input reader, and terminal output/diagnostic writers. Command
  handlers and stateful rendering helpers are methods; pure parsers/formatters
  remain functions.
- `New(input, output)` creates an independent Enterprise session with colors
  enabled. Nil input behaves as EOF and nil output discards messages. Matrix
  tactic-order slices are copied so sessions do not share mutable selections.
- The package-level `Run(args, version)` remains the executable-facing entrypoint
  and constructs a fresh app on `os.Stdin`/`os.Stdout`/`os.Stderr`. Those process
  streams are used only at that boundary. Tests supply readers/buffers without
  replacing process globals; combined-filter tests can now run in parallel.
- Mode selection, manual input, guided screens, and pagination share the same
  reader. A nested screen no longer creates a second buffer that can lose access
  to commands already read by the outer screen.
- Manual commands now pass through global option parsing. Matrix/plain selections
  persist for subsequent commands and when returning to the mode menu. Every new
  standalone invocation still starts with the default settings. Rejected global
  options leave the prior state unchanged rather than partially applying flags.
- Report metadata uses the session's paths rather than package globals.
- Spinner shutdown is idempotent and waits for its goroutine to finish before
  returning. A ticker replaces the fixed sleep, allowing shutdown to respond
  without waiting for the next frame and preventing overlap with later output.
- One `App` is intended for sequential use. Independent apps can run with separate
  streams; this does not make simultaneous commands on one app supported.

Tests cover independent session state/streams, copied tactic orders, rejected
options, manual option persistence, buffered scripts spanning pagination/guided
mode, session-specific report paths, EOF handling, and spinner shutdown. Run
`go test -race ./internal/cli` when changing session or spinner concurrency.

### Command Validation And Failures

- Command handlers return errors instead of printing failures themselves. One
  reporting boundary adds the error prefix and, for invalid usage, a help hint.
- `cli.Run` and `App.Run` return an exit code; only the root `main` calls `os.Exit`.
  Codes are `0` for success, `1` for operational failures, and `2` for invalid usage.
  Empty searches/mappings are successful; an explicitly requested missing entity
  is a failed lookup. Missing cache in `status` remains informational.
- `NewWithStreams(input, output, diagnostics)` allows separate writers. The
  executable uses stderr for failures; `New(input, output)` still combines both
  streams for simple consumers/tests. Manual mode ignores each command's exit
  code after reporting it, so a bad command does not terminate the session or
  contaminate a later successful command.
- Syntax validation precedes cache access. Shared operand/option-value checks
  prevent flags from being consumed as missing values; shared entity validation
  and export-target validation replace repeated checks. `show`, `status`, `help`,
  and non-technique lists no longer silently accept extra arguments/filters.
- Cache-loading errors include the selected matrix's update command. Missing
  update metadata is optional, but unreadable/malformed metadata is a failure.
  Updates that save the cache but fail to save metadata explicitly report the
  partial result. Reports are not written using silently discarded corrupt metadata.
- Export writing propagates close failures and validates the format before
  opening the destination. This does not make report writing atomic: a failed
  write can still leave a partial file.

Tests cover validation with absent caches, stderr separation, success/empty
results, missing entities/files, corrupt JSON, manual recovery, plain global
errors, report writes, and real entrypoint exit codes using bounded subprocesses.
Update-command failure tests use a local HTTP fixture server and temporary paths,
including cache/metadata write errors; no production dataset is downloaded.

### Regression Coverage

- A common synthetic cache is exercised through representative status, search,
  show, filtered/unfiltered lists, every entity mapping, and mapped export command
  for Enterprise, Mobile, and ICS. Each matrix uses its own tactic order, paths,
  names, IDs, and report output.
- The small STIX fixture is also normalized and passed through CLI detail,
  relationship, detection/analytic/component, and export commands. This protects
  the boundary between parser output and command behavior rather than testing
  those layers only in isolation.
- Every guided explorer branch is driven with bounded subprocess input for all
  three matrices. Tests cover details, mapped results, hiding already-viewed
  options, empty sections, invalid selections, missing-cache recovery, and clean
  returns to the guided menu. A timeout prevents a navigation regression from
  hanging CI or producing unbounded output.
- Pagination tests cover next/previous navigation, first/last-page boundaries,
  invalid choices, default page size, and empty rows.
- Manual mode now parses quoted multiword arguments and backslash escapes, making
  commands such as `list techniques --data-component "Process Creation"` behave
  like their standalone shell equivalents. Unterminated quotes/escapes report
  invalid usage without closing the session; no shell expansion or execution is
  performed.
