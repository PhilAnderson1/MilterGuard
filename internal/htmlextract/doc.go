// Package htmlextract derives a presentation-aware representation of an HTML
// email for downstream message extraction.
//
// It parses HTML and embedded CSS without executing scripts or fetching
// external resources. Text and relevant elements are classified as visible,
// concealed, client-dependent, or unknown using bounded evaluation intended
// for untrusted email input.
//
// The raw HTML and cumulative CSS sizes have independent limits. A single
// monotonic allocation budget is shared by the forked HTML and CSS parsers,
// selector compiler, DOM collection, cascade evaluation, and extraction.
// CPU use is sampled cooperatively inside the same parser and traversal loops.
package htmlextract
