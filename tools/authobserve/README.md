# Isolated authentication observation

This setup runs the trusted-header and internal authentication paths at the
same time on loopback-only, otherwise unused Milter listeners. It does not
change Postfix, systemd, or the production MilterGuard service. Both instances
run in monitor mode, use separate SQLite databases, and call a deterministic
local endpoint so AI output cannot obscure authentication differences.

From the repository root, prepare and validate the setup:

```sh
mkdir -p local-testing/auth-observation bin
go build -o bin/milterguard-auth-observe ./cmd/milterguard
bin/milterguard-auth-observe --config tools/authobserve/trusted.yaml --check-config --check-port
bin/milterguard-auth-observe --config tools/authobserve/internal.yaml --check-config --check-port
```

Start these three commands in separate terminals:

```sh
python3 tools/authobserve/mock_ai.py
bin/milterguard-auth-observe --config tools/authobserve/trusted.yaml
bin/milterguard-auth-observe --config tools/authobserve/internal.yaml
```

Replay the same directory through both listeners. The explicit receiver IP
also supplies Postfix's `{daemon_addr}` macro, which is needed by uncommon SPF
macros:

```sh
python3 tools/replay_mailbox.py local-testing/test_emails/legitimate \
  --port 18995 --receiver-ip 127.0.0.1 >local-testing/auth-observation/trusted.jsonl
python3 tools/replay_mailbox.py local-testing/test_emails/legitimate \
  --port 18996 --receiver-ip 127.0.0.1 >local-testing/auth-observation/internal.jsonl
```

Each record includes the saved `Authentication-Results` values and headers
added by the observed instance. Internal mode ignores saved authentication
fields while leaving them unchanged; trusted mode consumes configured local
results from those fields. Stop all three processes with Ctrl-C after the
bounded observation window.

The replay is deliberately byte-preserving for header names, order,
duplicates, whitespace, and folding. It reconstructs the exact header callback
form used by Postfix rather than parsing and reserializing the message, because
that would invalidate some DKIM signatures.
