# Mox dependency audit

Audit date: 2026-09-26

Decision: **GO**, with resolver isolation required before the verifier is wired
into production. Pin `github.com/mjl-/mox` at `v0.0.17`. Mox is pre-v1, so its
API is not covered by Go's v1 compatibility guarantee and upgrades require an
explicit API and behavior review.

## Version selection

The Go module proxy lists `v0.0.17` as the newest tagged release. It is also the
version used by the exact-DKIM feasibility prototype and declares Go 1.25,
matching MilterGuard's module.

## Module graphs

Adding Mox expands Go's minimum-version-selection graph by 22 modules even
though only 11 of them are linked by the authentication packages:

`github.com/beorn7/perks`, `github.com/cespare/xxhash/v2`,
`github.com/matttproud/golang_protobuf_extensions/v2`, `github.com/mjl-/adns`,
`github.com/mjl-/autocert`, `github.com/mjl-/bstore`, `github.com/mjl-/flate`,
`github.com/mjl-/mox`, `github.com/mjl-/sconf`, `github.com/mjl-/sherpa`,
`github.com/mjl-/sherpadoc`, `github.com/mjl-/sherpaprom`,
`github.com/mjl-/sherpats`, `github.com/mjl-/xfmt`,
`github.com/prometheus/client_golang`, `github.com/prometheus/client_model`,
`github.com/prometheus/common`, `github.com/prometheus/procfs`,
`github.com/russross/blackfriday/v2`, `go.etcd.io/bbolt`,
`google.golang.org/protobuf`, and `rsc.io/qr`.

It also raises `golang.org/x/mod` from v0.38.0 to v0.40.0 and
`golang.org/x/tools` from v0.48.0 to v0.49.0 in the module graph. Neither is
linked into the MilterGuard executable. This comparison used `go list -m all`
against the same revision before and after the Mox requirement.

### Compiled graph

Importing `mox/spf`, `mox/dkim` and `mox/dmarc` adds these modules to the
compiled dependency graph. `golang.org/x/net`, `golang.org/x/sys` and
`golang.org/x/text` are also in the graph but are already MilterGuard
dependencies at the same versions.

| Module | Version | New |
| --- | --- | --- |
| `github.com/mjl-/mox` | v0.0.17 | yes |
| `github.com/mjl-/adns` | v0.0.0-20260809141028-22f885debe71 | yes |
| `github.com/mjl-/flate` | v0.0.0-20250221133712-6372d09eb978 | yes |
| `github.com/prometheus/client_golang` | v1.18.0 | yes |
| `github.com/prometheus/client_model` | v0.5.0 | yes |
| `github.com/prometheus/common` | v0.45.0 | yes |
| `github.com/prometheus/procfs` | v0.12.0 | yes |
| `github.com/beorn7/perks` | v1.0.1 | yes |
| `github.com/cespare/xxhash/v2` | v2.2.0 | yes |
| `github.com/matttproud/golang_protobuf_extensions/v2` | v2.0.0 | yes |
| `google.golang.org/protobuf` | v1.31.0 | yes |
| `golang.org/x/net` | v0.58.0 | no |
| `golang.org/x/sys` | v0.47.0 | no |
| `golang.org/x/text` | v0.41.0 | no |

The linked graph was generated with `go list -deps` from a minimal Go 1.25
module that imports only the three Mox authentication packages. Licences are
distributed for these linked modules; unlinked graph-only modules are not part
of the executable or release artefacts.

## Static binary measurement

Both binaries were built with `CGO_ENABLED=0`, `-trimpath`, identical stripped
linker flags and the same MilterGuard source revision. The audit build retained
the SPF, DKIM, DMARC and strict-resolver entry points so the linker could not
discard their implementation.

| Build | Bytes | MiB |
| --- | ---: | ---: |
| Stage 1 baseline | 13,406,370 | 12.785 |
| Mox authentication packages | 17,211,554 | 16.414 |
| Increase | 3,805,184 | 3.629 |

The increase is 28.38%. This is acceptable for a statically linked service and
does not introduce a runtime package or process dependency. The measurement
must be repeated against the real verifier because final reachable code may
differ from the audit linkage shim.

## DNS and package initialization audit

Importing `mox/dns` executes an initializer that sets
`net.DefaultResolver.StrictErrors = true`. MilterGuard currently uses
`net.DefaultResolver` for connection reverse DNS, administration-command IP
lookups and the default RDAP resolver. Before importing Mox from production
code, those consumers must receive explicit `net.Resolver` instances with
their existing zero-value `StrictErrors` behavior. Regression tests must cover
partial A/AAAA failures, timeouts, and RDAP's resolve/validate/pinned-dial
sequence.

The dedicated authentication resolver will be `mox/dns.StrictResolver` backed
by its own `adns.Resolver`. It will not replace any existing MilterGuard
resolver. `adns` does not implement a persistent DNS response cache or expose
response TTLs; it coalesces concurrent lookups and briefly caches `/etc/hosts`
data. Positive and negative TTL caching therefore remains the responsibility
of the configured recursive DNS resolver. This avoids a permanent application
cache but means deployments need a suitable local or network recursive
resolver.

Other relevant initializers are:

- Mox `mlog` installs its package log-level defaults and registers logging
  counters through Prometheus.
- Prometheus initializes its default registry with Go and process collectors.
- Mox parses its embedded ICANN public-suffix snapshot at startup.
- Protobuf initializes generated descriptors.

None starts a goroutine, opens a listener or adds an external service. The
Prometheus registry is not exposed by MilterGuard, but its initialization and
binary cost remain part of the dependency footprint.

## Licensing

The new compiled modules use compatible MIT, BSD-3-Clause and Apache-2.0
licenses. Mox source is MIT licensed. Its embedded Mozilla Public Suffix List
snapshot is distributed under MPL-2.0. Exact licence texts, Apache NOTICE files
and the protobuf patent grant are included in `THIRD_PARTY_LICENSES` and listed
in `THIRD_PARTY_NOTICES.md`.

## Gate conditions for verifier implementation

The dependency audit passes subject to these implementation constraints:

1. Only the dedicated Mox adapter package may import Mox.
2. Existing DNS/RDAP consumers must be isolated from the global default
   resolver before that adapter is linked into the production binary.
3. Authentication uses a dedicated strict resolver and bounded concurrency and
   timeout controls.
4. No Mox, Prometheus or DNS types escape into MilterGuard session, policy or
   persistence state.
5. Static size and module/licence inventories are rechecked after the real
   verifier is linked.
