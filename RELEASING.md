# Releasing MilterGuard

Use this checklist before every release. Replace `X.Y.Z` with the proposed
version number; commands add the leading `v` where required.

## 1. Review dependencies

Compare the current Go toolchain with the latest stable release listed at
`https://go.dev/dl/`, then check every module for a newer release:

```sh
go version
go list -m -u all
```

Review each available update and its release notes. Apply updates deliberately,
then confirm that `go.mod` pins the versions intended for the release. Some
modules, notably `modernc.org/sqlite`, require an exact companion version of
`modernc.org/libc`; follow the upstream module file rather than choosing that
version independently.

Verify the downloaded module graph and scan the shipped application for known,
reachable vulnerabilities:

```sh
go mod verify
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./cmd/... ./internal/...
```

If a dependency or its licensing changes, update `THIRD_PARTY_NOTICES.md` and
the corresponding file under `THIRD_PARTY_LICENSES/`.

## 2. Review the parser forks

Dependabot and `go list -m -u` do not cover source copied into `internal/fork`.
Read the pinned tag and commit in each provenance file, then compare it with the
latest upstream release:

- `internal/fork/xnethtml/UPSTREAM.md` — `golang.org/x/net/html`
- `internal/fork/cascadia/UPSTREAM.md` — `github.com/andybalholm/cascadia`
- `internal/fork/tdewolffparse/UPSTREAM.md` — `github.com/tdewolff/parse/v2`

Review all upstream changes since the recorded commit, including security fixes,
parser corrections and tests. Record the outcome even when no source update is
needed. When updating a fork:

1. Start from the same upstream package scope recorded in `UPSTREAM.md` at the
   selected tag.
2. Preserve every applicable local change listed in `UPSTREAM.md`.
3. Retain the upstream licence and tests.
4. Update the tag, commit and local-change description in `UPSTREAM.md`.
5. Check that imports still use the MilterGuard-local HTML and atom types.
6. Run the fork, extraction and corpus tests before accepting the update.

Do not replace a fork mechanically: its resource guards, structural limits and
local APIs are part of MilterGuard's security boundary.

## 3. Validate the release candidate

Review the reference configuration and documentation for every user-visible
change. Ensure new configuration and support files are included by the tar,
Debian and RPM packaging paths.

Run the maintained application checks:

```sh
test -z "$(gofmt -l cmd internal)"
python3 -m py_compile tools/replay_mailbox.py
python3 -m unittest tools/replay_mailbox_test.py
go test ./cmd/... ./internal/...
go test -race ./internal/milter ./internal/admincmd ./internal/stores/...
go vet ./cmd/... ./internal/...
CGO_ENABLED=0 go build -trimpath \
  -o local-testing/milterguard-release-check ./cmd/milterguard
```

For changes affecting MIME, HTML or CSS processing, also run the maintained
email-corpus benchmark and compare it with the previous baseline:

```sh
GOMAXPROCS=2 go test ./local-testing/html-benchmark \
  -run '^$' -bench '^BenchmarkProcessedBodyHTMLCorpus$/all$' \
  -benchtime=5x -count=5 -benchmem
```

Replay representative legitimate, spam and scam mailboxes through a separate
test instance as described in `OPERATING_GUIDE.md`. Investigate output changes,
false positives, false negatives and material performance regressions.

## 4. Prepare the release

Commit and push the complete release candidate, then confirm that CI passes and
the version tag does not already exist:

```sh
git status --short
git tag -l vX.Y.Z
```

The build script requires a clean working tree. If the intentionally untracked
`local-only/` directory is present, inspect `git status` carefully and use
`--allow-dirty` only when every reported path is known and excluded from the
release:

```sh
./packaging/build-release.sh vX.Y.Z --allow-dirty
```

Otherwise build without that option:

```sh
./packaging/build-release.sh vX.Y.Z
```

The script reruns production tests, builds a statically linked Linux amd64
binary, checks its embedded version, and creates RPM, Debian and portable tar
packages plus a checksum manifest under `dist/`.

## 5. Verify the packages

Verify all generated checksums:

```sh
cd dist
sha256sum -c milterguard-vX.Y.Z-SHA256SUMS.txt
cd ..
```

Inspect each package and confirm that the binary, service, documentation,
configuration, endpoint catalogue, thinking-profile catalogue and replay tool
are present:

```sh
tar -tzf dist/milterguard-vX.Y.Z-linux-amd64.tar.gz
dpkg-deb -c dist/milterguard_X.Y.Z_amd64.deb
rpm -qpl dist/milterguard-X.Y.Z-1.x86_64.rpm
```

Where practical, install each format on a suitable test system. Confirm that a
new installation enables but does not start the service, configuration files
have the intended ownership and permissions, `--check-config` succeeds after
configuration, and upgrades preserve local settings.

## 6. Publish and verify

Write release notes covering highlights, configuration or operational changes,
downloads and validation. Save them under the ignored `local-testing/`
directory, then publish the release and its four assets:

```sh
gh release create vX.Y.Z \
  dist/milterguard-X.Y.Z-1.x86_64.rpm \
  dist/milterguard_X.Y.Z_amd64.deb \
  dist/milterguard-vX.Y.Z-linux-amd64.tar.gz \
  dist/milterguard-vX.Y.Z-SHA256SUMS.txt \
  --target main \
  --title "MilterGuard vX.Y.Z" \
  --notes-file local-testing/release-vX.Y.Z.md
```

Finally, open the published release, confirm it is neither a draft nor a
prerelease, verify that all four assets are present, and test the Quick Start
links against the new tag.
