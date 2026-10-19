# Allocation-effect review

The test compares production declaration fingerprints in `internal/htmlextract`
and `internal/fork` against `testdata/approved-effects.json`. It also rejects
direct `Reserve` and `TryReserve` calls in those packages: allocation accounting
belongs to the shared storage owners.

When a declaration changes, review its allocation effects and those of its
callees, including ownership, growth, failure handling and cancellation. Only
after that review should the approved manifest be updated from `Scan`'s result
(JSON encoded). Do not regenerate it merely to make a test pass.

This check requires human review of changed code; it is not an automatic proof
that all allocations are accounted for. Tests are excluded from fingerprinting.
