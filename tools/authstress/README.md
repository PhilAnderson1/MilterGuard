# Exact-message storage stress harness

`authstress` holds the configured number of maximum-size exact-message stores
open simultaneously, verifies their size and final byte, records Go heap and
file-descriptor counts, and closes every store. It performs no DNS lookups and
sends no mail.

Run the configured 64 × 10 MiB bound from the repository root:

```sh
go run ./tools/authstress -message-storage memory

mkdir -p .cache/authstress-tmp
TMPDIR="$PWD/.cache/authstress-tmp" \
  go run ./tools/authstress -message-storage file
```

Use a disk-backed `TMPDIR` for the file test. The default `/tmp` is commonly a
small tmpfs; filling it would measure RAM and may disrupt unrelated services.
File stores are unlinked immediately, so directory listings remain empty while
their descriptors retain the logical data until close.
