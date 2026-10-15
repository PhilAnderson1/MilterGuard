# Upstream provenance

This directory is a source fork of `golang.org/x/net/html` from tag
`v0.61.0`, commit `c1d31df183e51b1075a2fd670d6f6f4efb871773`.

The root `html` package and its `atom` and `charset` subpackages were copied.
Imports were rewritten to the MilterGuard-local package paths. A parser option
charges tokenizer buffers, nodes, attributes, parser stacks, and text merges
to a shared monotonic memory budget and samples cooperative cancellation. The
upstream 512-open-element panic was removed because the shared guards now bound
that state. Keep these changes explicit when reviewing later upstream updates.

The upstream BSD licence and patent notice are retained as `LICENSE` and
`PATENTS`.
