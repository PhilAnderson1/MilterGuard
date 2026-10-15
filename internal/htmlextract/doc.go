// Package htmlextract derives a presentation-aware representation of an HTML
// email for downstream message extraction.
//
// It parses HTML and embedded CSS without executing scripts or fetching
// external resources. Text and relevant elements are classified as visible,
// concealed, client-dependent, or unknown using bounded evaluation intended
// for untrusted email input.
//
// Parsing and analysis use explicit stacks rather than recursion. The forked
// HTML parser enforces resource limits while tokenizing and building the tree;
// document collection and presentation analysis then apply their own bounded
// traversals for the state each pass needs.
package htmlextract
