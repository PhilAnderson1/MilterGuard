# Exact-DKIM feasibility prototype

This directory is intentionally outside the production Go module. It records
the literal Milter protocol payloads sent by a real Postfix instance before any
production integration work begins.

The capture JSON records every command payload in hexadecimal. Header commands
also have decoded `name` and `value` fields for readability; the hexadecimal
form is authoritative. Body payloads are never decoded or normalised.

This is an experimental harness, not a MilterGuard component.
