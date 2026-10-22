// Package resourceguard owns cumulative allocation admission for extraction.
//
// New/Box own fixed objects, MakeSlice/GrowSlice/Append and byte operations own
// backing arrays, text operations own immutable strings, and Table owns native
// map policy. Every replacement is charged in full; there are no refunds. Nil
// budgets disable accounting. Required failure records exhaustion and unwinds
// with termination.MemoryExceeded; it never returns a failure Boolean or error.
// Try operations may decline optional storage that does not fit without
// poisoning required work. They are not recovery operations: a valid storage
// request against an already-exhausted ledger terminates the stage. APIs that
// validate dimensions or indexes panic on invalid arguments before consulting
// the ledger, keeping programmer errors distinct from document exhaustion.
//
// Typed arrays charge requested payload; fixed objects round to 16 bytes. Byte
// buffers and builders reconcile exposed capacity before publication. Native
// maps, callback environments and library workspaces use conservative policies
// in this package, not exact runtime layouts. Compiler/runtime setup, diagnostic
// failure objects, process initialization and intentionally unguarded auxiliary
// APIs are outside the extraction ledger. These policies account for cumulative
// pressure, not live heap or process memory. Revalidate library allowances when
// upgrading Go. See internal/allocationaudit/README.md for the required review
// and fingerprint-approval procedure for changes to htmlextract and the forks.
package resourceguard
