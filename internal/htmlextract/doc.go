// Package htmlextract derives a presentation-aware representation of an HTML
// email for downstream message extraction.
//
// It parses HTML and embedded CSS without executing scripts or fetching
// external resources. Text and relevant elements are classified as visible,
// concealed, client-dependent, or unknown using bounded evaluation intended
// for untrusted email input.
//
// Parsing and analysis use separate explicit stacks rather than recursion.
// Input depth is attacker-controlled, and each pass carries different state:
// the preflight tracks lexical nesting, document collection tracks the parsed
// tree, and presentation analysis tracks inherited styles and paint layers.
// Keeping those stacks separate preserves their distinct limits and failure
// semantics.
package htmlextract
