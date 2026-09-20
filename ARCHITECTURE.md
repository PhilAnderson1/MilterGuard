# MilterGuard Architecture

This document is a guide to the source code. It describes package ownership,
the principal execution paths, and the boundaries that should remain intact
when MilterGuard is changed.

## Executable and operating modes

`cmd/milterguard` is the composition root. It loads and validates configuration,
sets up logging, and selects one of three paths:

- Normal service mode constructs the AI client and Milter server, opens the
  configured listener, and serves Postfix connections.
- Command mode opens the live SQLite database and runs administration commands
  entered on standard input.
- Configuration, port, and endpoint checks validate specific parts of an
  installation without starting the server.

The executable should contain startup and presentation logic, not filtering
policy or persistence queries.

## Package map

| Package | Responsibility |
| --- | --- |
| `internal/admincmd` | Parses and executes administration commands independently of their email or terminal transport. |
| `internal/ai` | Builds chat-completions requests, applies endpoint retries, and validates AI decisions. |
| `internal/attachment` | Detects prohibited executable attachments and inspects supported archives. |
| `internal/config` | Loads defaults, strictly decodes YAML, and validates cross-setting requirements. |
| `internal/mailauth` | Parses trusted Authentication-Results data and evaluates domain alignment. |
| `internal/message` | Accumulates SMTP message data and produces bounded, decoded text, links, images, and authentication evidence. |
| `internal/milter` | Implements the Milter protocol, session state, filtering policy, service orchestration, and Postfix responses. |
| `internal/netsafety` | Normalizes DNS hostnames and rejects unsafe or non-public network destinations. |
| `internal/rdap` | Discovers and queries RDAP services with redirect, SSRF, and DNS-rebinding protection. |
| `internal/rejectedmail` | Saves and cleans up rejected `.eml` files beneath the configured archive root. |
| `internal/smtpreply` | Builds MIME command replies and submits them to the configured SMTP service. |
| `internal/sqlitedb` | Owns SQLite connection setup, schema migration, WAL handling, busy retries, transactions, and checkpoints. |
| `internal/stores` | Defines SQL-independent repository interfaces, queries, and value types. |
| `internal/stores/sqlite` | Implements the repository contracts with indexed SQLite operations. |

The dependency direction is intentional. Protocol and policy code depends on
interfaces in `stores`; concrete SQL is confined to `stores/sqlite`, while
connection-level database mechanics remain in `sqlitedb`.

## Service construction

Normal service construction begins in `milter.NewServer` and
`milter.buildRuntime`. Runtime construction:

1. Opens SQLite when an enabled feature requires persistent state.
2. Constructs the four configured repositories.
3. Builds IP-reputation and domain-registration policy services around those
   repositories.
4. Creates the rejected-message archive, attachment scanner, command
   processor, AI service, and SMTP reply sender as required.
5. Groups those dependencies into analysis, policy, attachment, command,
   connection-DNS, maintenance, and session services.

Sessions receive explicit service dependencies. They do not reach back through
the complete `Server` to locate unrelated functionality.

## Inbound message flow

```text
Postfix connection
  -> Milter frame parsing and session state
  -> connection and envelope checks
  -> message headers and body accumulation
  -> deterministic policies requiring the complete message
  -> MIME, text, link and image extraction
  -> trusted authentication evidence
  -> correspondent and domain-registration evidence
  -> AI classification when no deterministic result applies
  -> accept, tag, reject or temporary failure response
  -> asynchronous reputation and correspondent updates
  -> rejection record and optional original-message archive
```

`session.run` owns one Milter connection. It decodes frames, checks protocol
phase transitions, and dispatches commands. `session.finishMessage` coordinates
the end-of-message path and sends exactly one final Milter response.

Deterministic policies run before AI analysis where possible. Examples include
cached IP blocks, authenticated-only sender domains, prohibited attachments,
trusted correspondents, authenticated-submission bypasses, and trusted sender
domains. This avoids unnecessary endpoint work and keeps unambiguous security
decisions independent of model output.

## Message and authentication processing

`internal/message` owns decoding and evidence extraction. It parses MIME,
decodes transfer and header encodings, turns HTML into bounded visible text,
preserves useful link and image references, and prepares inline images for
vision analysis. The same archived-message parser is used by `REJECTION <id>`
so command output reflects the current message-processing implementation.

`internal/mailauth` is the authoritative Authentication-Results parser. Only
results whose authentication-service identifiers are trusted by configuration
are used as local evidence. Postfix is still responsible for removing supplied
Authentication-Results headers before authentication Milters add fresh local
results.

## AI analysis

The Milter analysis service builds an `ai.Input` from the already processed
message and connection evidence. `internal/ai` owns HTTP communication with the
configured chat-completions endpoint, bounded retries, response-size limits,
and strict decision decoding.

The AI result is policy input rather than the final action. The Milter layer
applies mode and confidence thresholds to choose the proposed and actual
actions. Endpoint failures follow the configured failure action and do not
create legitimate-sender evidence.

## Post-decision state changes

After the Milter response has been determined, policy updates may:

- Add or decay IP-reputation strikes.
- Learn or update correspondent records.
- Write rejection history.
- Save the original rejected message.

These updates are bounded by a separate timeout and occur outside the critical
response path where possible. Monitor and tag modes do not mutate adaptive
reputation or correspondent state.

## Persistence

`internal/sqlitedb` owns one process's SQLite connection pool and configures
WAL mode, the busy timeout, schema versions, migrations, retryable busy
handling, and checkpoints.

Repository behavior lives in `internal/stores/sqlite`:

- Correspondents support policy learning and administration operations.
- IP reputation stores strikes and active short or repeat blocks.
- Rejections store one event with all affected local recipients.
- Domain registrations cache registration and expiration dates.

Expired rows and capacity excess are removed during periodic maintenance.
Queries must independently exclude expired data when stale rows must not be
visible between cleanup passes.

The Milter service and standalone command mode may access the database
concurrently. WAL mode, short transactions, the busy timeout, and bounded busy
retries coordinate that access.

## Domain-registration lookup

The Milter domain-registration service owns cache decisions, failed-lookup
suppression, per-domain request coalescing, lookup concurrency, persistence,
and conversion to AI evidence.

`internal/rdap` owns only network discovery and lookup. It loads the IANA
bootstrap, selects services by TLD, validates redirects, resolves endpoints,
rejects non-public addresses, and dials the validated address directly to
prevent DNS rebinding. Shared hostname and address validation is provided by
`internal/netsafety`.

## Administration commands

`internal/admincmd` contains command syntax, authorization-aware query scope,
database operations, output formatting, and deferred rejection-detail
rendering. It is used by:

- Interactive or piped command mode in `cmd/milterguard`.
- Authenticated email commands handled by the Milter session.

`REJECTION <id>` defers archive reading and MIME processing until the response
is rendered. For email commands this keeps archive parsing off the Milter
end-of-message path. `internal/smtpreply` subsequently formats and submits the
reply; the Milter command service owns reply concurrency, logging, and panic
recovery.

## Concurrency and lifecycle ownership

- `Server` owns the listener, accepted connections, connection limit, database
  lifetime, and maintenance goroutines.
- Each `session` owns one connection and its message state.
- The analysis service owns the AI concurrency semaphore.
- The attachment service owns attachment-scan concurrency.
- The domain-registration service owns lookup concurrency and duplicate lookup
  suppression.
- The email-command service owns reply goroutines and their semaphore.
- RDAP, SMTP reply, and SQLite clients own only operations or connections
  created for their individual calls.

Long-running end-of-message AI work sends periodic Milter progress responses.
Panics at goroutine and session boundaries are recovered and logged so one
message cannot terminate the service.

## Security boundaries

Important trust boundaries include:

- Postfix peer restrictions determine who may speak the Milter protocol.
- Postfix authentication macros identify authenticated SMTP submissions.
- Trusted Authentication-Results identifiers distinguish locally calculated
  evidence from supplied headers.
- Administration email authorization ties authenticated identities to allowed
  local sender addresses.
- `netsafety` and RDAP pinned dialing prevent requests to internal services.
- Message content, images, and links are always treated as untrusted data by
  the AI request.
- Rejected-message archive paths are constructed beneath one configured root.

Changes at these boundaries should retain explicit validation and focused
tests rather than relying on caller assumptions.

## Testing strategy

Package tests cover parsing, policy, repositories, network safeguards, and
protocol behavior. Cross-component Milter tests exercise complete session
paths with injected services. Race tests cover the principal concurrent
packages and repository use.

For changes that affect runtime wiring, run at least:

```sh
go test ./cmd/... ./internal/...
go test -race ./internal/milter ./internal/admincmd ./internal/stores/...
go vet ./cmd/... ./internal/...
```

The release build is compiled statically and both distributed configuration
files should pass `--check-config` before installation.
