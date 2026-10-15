# Upstream provenance

This directory is a source fork of `github.com/andybalholm/cascadia` from tag
`v1.3.5`, commit `caa0b274f513cca28d83d3a13d924eac07e28e84`.

The complete selector package and its upstream tests were copied. Its HTML and atom imports were rewritten to use the
MilterGuard-local `x/net/html` fork so all selector APIs share one node type.

MilterGuard adds selector-compilation allocation charging and replaces the
upstream nesting-count ceiling with reservations against the same shared
memory budget used by HTML and CSS parsing.

The upstream BSD licence is retained as `LICENSE`.
