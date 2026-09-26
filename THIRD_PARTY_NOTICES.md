# Third-party notices

MilterGuard is distributed under its own licence in `LICENSE`. Its compiled
binary also incorporates the following third-party software. The corresponding
licence texts are reproduced verbatim in `THIRD_PARTY_LICENSES`.

| Software | Version | Licence and notice files |
| --- | --- | --- |
| github.com/beorn7/perks | v1.0.1 | `github.com-beorn7-perks.txt` |
| github.com/cespare/xxhash/v2 | v2.2.0 | `github.com-cespare-xxhash-v2.txt` |
| Go standard library | Go 1.25 or later | `go-standard-library.txt` |
| github.com/dustin/go-humanize | v1.0.1 | `github.com-dustin-go-humanize.txt` |
| github.com/google/uuid | v1.6.0 | `github.com-google-uuid.txt` |
| github.com/mattn/go-isatty | v0.0.24 | `github.com-mattn-go-isatty.txt` |
| github.com/mattn/go-runewidth | v0.0.3 | `github.com-mattn-go-runewidth.txt` |
| github.com/matttproud/golang_protobuf_extensions/v2 | v2.0.0 | `apache-2.0.txt`, `github.com-matttproud-golang-protobuf-extensions-v2-notice.txt` |
| github.com/mjl-/adns | v0.0.0-20260809141028-22f885debe71 | `github.com-mjl-adns.txt` |
| github.com/mjl-/flate | v0.0.0-20250221133712-6372d09eb978 | `github.com-mjl-flate.txt` |
| github.com/mjl-/mox | v0.0.17 | `github.com-mjl-mox.txt` |
| github.com/peterh/liner | v1.2.2 | `github.com-peterh-liner.txt` |
| github.com/prometheus/client_golang | v1.18.0 | `apache-2.0.txt`, `github.com-prometheus-client-golang-notice.txt` |
| github.com/prometheus/client_model | v0.5.0 | `apache-2.0.txt`, `github.com-prometheus-client-model-notice.txt` |
| github.com/prometheus/common | v0.45.0 | `apache-2.0.txt`, `github.com-prometheus-common-notice.txt` |
| github.com/prometheus/procfs | v0.12.0 | `apache-2.0.txt`, `github.com-prometheus-procfs-notice.txt` |
| github.com/remyoudompheng/bigfft | v0.0.0-20230129092748-24d4a6f8daec | `github.com-remyoudompheng-bigfft.txt` |
| golang.org/x/net | v0.58.0 | `golang.org-x-net.txt` |
| golang.org/x/sys | v0.47.0 | `golang.org-x-sys.txt` |
| golang.org/x/text | v0.41.0 | `golang.org-x-text.txt` |
| google.golang.org/protobuf | v1.31.0 | `google.golang.org-protobuf.txt`, `google.golang.org-protobuf-patents.txt` |
| gopkg.in/yaml.v3 | v3.0.1 | `gopkg.in-yaml.v3.txt` |
| Mozilla Public Suffix List data embedded by Mox | Mox v0.0.17 snapshot | `mozilla-public-license-2.0.txt` |
| modernc.org/libc | v1.75.6 | `modernc.org-libc.txt` |
| Third-party code incorporated by modernc.org/libc | bundled with v1.75.6 | `modernc.org-libc-third-party.md` |
| modernc.org/mathutil | v1.7.1 | `modernc.org-mathutil.txt` |
| modernc.org/memory | v1.12.1 | `modernc.org-memory.txt` |
| mmap-go code incorporated by modernc.org/memory | bundled with v1.12.1 | `modernc.org-memory-mmap-go.txt` |
| modernc.org/sqlite | v1.58.0 | `modernc.org-sqlite.txt` |
| SQLite incorporated by modernc.org/sqlite | bundled with v1.58.0 | `sqlite-public-domain.txt` |
| sqlite-vec incorporated by modernc.org/sqlite | bundled with v1.58.0 | `sqlite-vec.txt` |

This inventory covers the external modules compiled into the MilterGuard
executable. Module versions and the minimum supported Go version are recorded
in `go.mod`. It should be reviewed whenever dependencies are added or updated.

The Mox authentication rows and their transitive dependencies were added during
the Stage 2 dependency gate. They are pinned and ready for distribution but do
not enter the executable until the dedicated verifier package is linked.
