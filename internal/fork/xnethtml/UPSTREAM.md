# Upstream provenance

This directory is a source fork of `golang.org/x/net/html` from tag
`v0.61.0`, commit `c1d31df183e51b1075a2fd670d6f6f4efb871773`.

The root `html` package and its `atom` and `charset` subpackages were copied
without functional changes. Imports were rewritten to the MilterGuard-local
package paths. Keep local resource-accounting changes separate and clearly
marked so later upstream security and correctness fixes can be reviewed.

The upstream BSD licence and patent notice are retained as `LICENSE` and
`PATENTS`.
