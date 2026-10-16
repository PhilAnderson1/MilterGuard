# Third-party notices

MilterGuard is distributed under its own licence in `LICENSE`. Its compiled
binary also incorporates the following third-party software. The corresponding
licence texts are reproduced verbatim in `THIRD_PARTY_LICENSES`.

| Software | Version | Licence and notice files |
| --- | --- | --- |
| github.com/andybalholm/cascadia (source fork) | v1.3.5 | `github.com-andybalholm-cascadia.txt` |
| github.com/beorn7/perks | v1.0.1 | `github.com-beorn7-perks.txt` |
| github.com/cespare/xxhash/v2 | v2.3.0 | `github.com-cespare-xxhash-v2.txt` |
| github.com/clipperhouse/uax29/v2 | v2.7.0 | `github.com-clipperhouse-uax29-v2.txt` |
| Go standard library | Go 1.26 or later | `go-standard-library.txt` |
| github.com/dustin/go-humanize | v1.1.0 | `github.com-dustin-go-humanize.txt` |
| github.com/google/uuid | v1.6.0 | `github.com-google-uuid.txt` |
| github.com/mattn/go-isatty | v0.0.24 | `github.com-mattn-go-isatty.txt` |
| github.com/mattn/go-runewidth | v0.0.31 | `github.com-mattn-go-runewidth.txt` |
| github.com/mjl-/adns | v0.0.0-20260809141028-22f885debe71 | `github.com-mjl-adns.txt` |
| github.com/mjl-/flate | v0.0.0-20250221133712-6372d09eb978 | `github.com-mjl-flate.txt` |
| github.com/mjl-/mox | v0.0.17 | `github.com-mjl-mox.txt` |
| github.com/munnerz/goautoneg | v0.0.0-20191010083416-a7dc8b61c822 | `github.com-munnerz-goautoneg.txt` |
| github.com/peterh/liner | v1.2.3 | `github.com-peterh-liner.txt` |
| github.com/prometheus/client_golang | v1.25.0 | `apache-2.0.txt`, `github.com-prometheus-client-golang-notice.txt` |
| github.com/prometheus/client_model | v0.6.3 | `apache-2.0.txt`, `github.com-prometheus-client-model-notice.txt` |
| github.com/prometheus/common | v0.72.1 | `apache-2.0.txt`, `github.com-prometheus-common-notice.txt` |
| github.com/prometheus/procfs | v0.22.0 | `apache-2.0.txt`, `github.com-prometheus-procfs-notice.txt` |
| github.com/remyoudompheng/bigfft | v0.0.0-20230129092748-24d4a6f8daec | `github.com-remyoudompheng-bigfft.txt` |
| github.com/tdewolff/parse/v2 (source fork) | v2.8.18 | `github.com-tdewolff-parse-v2.txt` |
| golang.org/x/net/html (source fork) | x/net v0.61.0 | `golang.org-x-net.txt` |
| golang.org/x/net | v0.61.0 | `golang.org-x-net.txt` |
| golang.org/x/sys | v0.49.0 | `golang.org-x-sys.txt` |
| golang.org/x/text | v0.43.0 | `golang.org-x-text.txt` |
| google.golang.org/protobuf | v1.36.12 | `google.golang.org-protobuf.txt`, `google.golang.org-protobuf-patents.txt` |
| gopkg.in/yaml.v3 | v3.0.1 | `gopkg.in-yaml.v3.txt` |
| Mozilla Public Suffix List data embedded by Mox | Mox v0.0.17 snapshot | `mozilla-public-license-2.0.txt` |
| modernc.org/libc | v1.77.1 | `modernc.org-libc.txt` |
| Third-party code incorporated by modernc.org/libc | bundled with v1.77.1 | `modernc.org-libc-third-party.md` |
| modernc.org/mathutil | v1.7.1 | `modernc.org-mathutil.txt` |
| modernc.org/memory | v1.12.1 | `modernc.org-memory.txt` |
| mmap-go code incorporated by modernc.org/memory | bundled with v1.12.1 | `modernc.org-memory-mmap-go.txt` |
| modernc.org/sqlite | v1.60.1 | `modernc.org-sqlite.txt` |
| Third-party code incorporated by modernc.org/sqlite | bundled with v1.60.1 | `modernc.org-sqlite-third-party.md` |
| SQLite incorporated by modernc.org/sqlite | bundled with v1.60.1 | `sqlite-public-domain.txt` |
| sqlite-vec incorporated by modernc.org/sqlite | bundled with v1.60.1 | `sqlite-vec.txt` |

This inventory covers the external modules compiled into the MilterGuard
executable. Module versions and the minimum supported Go version are recorded
in `go.mod`. It should be reviewed whenever dependencies are added or updated.

The Mox authentication rows and their transitive dependencies were added during
the Stage 2 dependency gate. They are pinned and ready for distribution but do
not enter the executable until the dedicated verifier package is linked.
