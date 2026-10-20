// Package resourceguard owns cumulative allocation admission for extraction.
//
// New/Box own fixed objects, MakeSlice/GrowSlice/Append and byte operations own
// backing arrays, text operations own immutable strings, and Table owns native
// map policy. Every replacement is charged in full; there are no refunds. Nil
// budgets disable accounting. Required failure records exhaustion and unwinds
// with termination.MemoryExceeded; it never returns a failure Boolean or error.
// Try operations may decline optional storage without poisoning required work.
//
// Typed arrays charge requested payload; fixed objects round to 16 bytes. Byte
// buffers and builders reconcile exposed capacity before publication. Native
// maps, callback environments and library workspaces use conservative policies
// in this package, not exact runtime layouts. Compiler/runtime setup, diagnostic
// failure objects, process initialization and auxiliary APIs have explicit
// exceptions in local-testing/allocation-audit/README.md. These policies are cumulative
// pressure accounting, not a promise about live heap or process memory.
package resourceguard
