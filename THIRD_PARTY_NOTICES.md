# Third-party notices

MilterGuard is distributed under its own licence in `LICENSE`. Its compiled
binary also incorporates the following third-party software. The corresponding
licence texts are reproduced verbatim in `THIRD_PARTY_LICENSES`.

| Software | Version | Licence file |
| --- | --- | --- |
| Go standard library | Go 1.26.7 | `go-standard-library.txt` |
| github.com/dustin/go-humanize | v1.0.1 | `github.com-dustin-go-humanize.txt` |
| github.com/google/uuid | v1.6.0 | `github.com-google-uuid.txt` |
| github.com/remyoudompheng/bigfft | v0.0.0-20230129092748-24d4a6f8daec | `github.com-remyoudompheng-bigfft.txt` |
| golang.org/x/net | v0.58.0 | `golang.org-x-net.txt` |
| golang.org/x/sys | v0.47.0 | `golang.org-x-sys.txt` |
| golang.org/x/text | v0.41.0 | `golang.org-x-text.txt` |
| gopkg.in/yaml.v3 | v3.0.1 | `gopkg.in-yaml.v3.txt` |
| modernc.org/libc | v1.75.6 | `modernc.org-libc.txt` |
| Third-party code incorporated by modernc.org/libc | bundled with v1.75.6 | `modernc.org-libc-third-party.md` |
| modernc.org/mathutil | v1.7.1 | `modernc.org-mathutil.txt` |
| modernc.org/memory | v1.12.1 | `modernc.org-memory.txt` |
| mmap-go code incorporated by modernc.org/memory | bundled with v1.12.1 | `modernc.org-memory-mmap-go.txt` |
| modernc.org/sqlite | v1.58.0 | `modernc.org-sqlite.txt` |
| SQLite incorporated by modernc.org/sqlite | bundled with v1.58.0 | `sqlite-public-domain.txt` |
| sqlite-vec incorporated by modernc.org/sqlite | bundled with v1.58.0 | `sqlite-vec.txt` |

This inventory covers the external modules compiled into the MilterGuard
executable at the versions recorded in `go.mod`. It should be reviewed whenever
dependencies are added or updated.
