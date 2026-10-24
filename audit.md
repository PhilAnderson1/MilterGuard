# Security audit findings

Audit date: 2026-10-24.

## 1. High — Authentication properties can be confused with attacker-controlled values

**Status:** Fixed in the working tree. Authentication properties are now parsed as complete assignments; embedded property-like text is ignored, and duplicate or malformed assignments cannot supply domain-authentication evidence. Regression tests cover DKIM, DMARC, SPF, and the Received-SPF fallback.

**References:** `mailauth.Parse` in [internal/mailauth/authentication_results.go](internal/mailauth/authentication_results.go:24).

DKIM and DMARC domains are extracted using regular expressions over the entire clause. The following input incorrectly authenticates `victim.example`:

```text
mx.example; dkim=pass header.i=header.d=victim.example@attacker.example header.d=attacker.example
```

The reproducer confirmed `DKIMAligned=true` for `victim.example`. In `trusted_headers` mode, exploitation depends on the trusted upstream emitting the attacker-controlled identity before the real domain. This can enable authentication-dependent filtering bypasses.

**Suggested fix:** Parse complete property/value tokens, never search inside another property's value, and reject ambiguous duplicate domain properties.

## 2. Policy consideration — Incomplete archive inspection follows the configured action

**Status:** Configurable policy tradeoff, not a bypass of a configured reject policy. The built-in and example-config defaults now use `unscannable_action: reject`. The default rejection wording also covers incomplete inspection without claiming an executable was detected. Existing configurations that explicitly select `accept` retain that policy.

**References:** `Scanner.scanZIP` in [internal/attachment/scanner.go](internal/attachment/scanner.go:317); `attachmentPolicyService.evaluate` in [internal/milter/attachment_policy.go](internal/milter/attachment_policy.go:48); [default unscannable action](configs/milterguard.yaml:297).

ZIP inspection stops at the first inspection error. A reproduced ZIP containing 101 harmless files followed by `payload.exe` returned only a file-count error. At the time of the audit, the default `unscannable_action: accept` continued with AI analysis without inspecting the executable. The new `reject` default rejects this message in enforce mode.

**Policy options:** Operators who require complete attachment inspection can set `attachments.unscannable_action: reject` in enforce mode. `tempfail` is also supported; `accept` intentionally allows normal AI analysis to continue. Rejection for incomplete inspection does not add an IP reputation strike. The reproducer establishes the behavior, not how frequently it occurs in practice.

## 3. High — Rejected-mail storage can exhaust the disk between cleanups

**References:** `Archive.saveAt` in [internal/rejectedmail/archive.go](internal/rejectedmail/archive.go:160); `maintenanceService.runDailyCleanup` in [internal/milter/maintenance.go](internal/milter/maintenance.go:114).

Archive writes compare each individual message against `MaxTotalBytes`; they do not enforce aggregate usage. Aggregate enforcement runs during daily cleanup. A reproducer successfully saved three 80-byte messages with a 100-byte total limit. With archiving enabled by default, repeated rejected mail can fill the filesystem containing archives and the database.

**Suggested fix:** Reserve aggregate capacity atomically before each write, evict or skip archiving when full, and enforce a free-space floor.

## 4. High, when email commands are enabled — Reply size checks occur after potentially gigabyte-scale allocations

**Status:** Fixed in the working tree. Replies now share an attachment budget derived from `milter.max_message_size`, reserve space for text and encoding overhead, and check each archive's size before loading it. Oversized attachments are omitted with a notice; duplicate requests do not reload the same attachment. Final size measurement does not construct the payload, and encoding enforces the byte limit while writing base64 in small chunks.

**References:** `handleEmailCommand` in [internal/milter/email_commands.go](internal/milter/email_commands.go:147); `buildBoundedCommandReplyMessage` in [internal/milter/email_commands.go](internal/milter/email_commands.go:347).

Command handling accumulates archived attachments from up to 100 commands. Reply construction then fully MIME/base64-encodes them before checking `maxBytes`. An authorized ordinary user requesting many large archived messages for their own mailbox can exhaust memory; four reply workers may run concurrently. This finding follows from the allocation and size-check ordering in the code; a gigabyte-scale exhaustion test was not run.

**Suggested fix:** Apply a shared attachment-byte budget before reading each archive, account for encoding overhead before appending attachments, and render through a size-limited writer.

## 5. Medium — ZIP metadata processing bypasses the configured entry budget

**Status:** Fixed in the working tree. ZIP central-directory records are counted before the standard ZIP reader allocates its file list, including directories and records hidden by forged counts or offsets. Nested and sibling archives share the entry budget and a 1 MiB ZIP metadata budget. Parsing checks cancellation. Regression tests cover entry floods, ZIP64, prefixes, forged metadata, cumulative limits, and bounded allocations.

**References:** `Scanner.scanZIP` in [internal/attachment/scanner.go](internal/attachment/scanner.go:317).

ZIP scanning calls `zip.NewReader` before enforcing entry limits, and directory entries never count toward that limit. A 4.8 MB ZIP containing 60,000 directories allocated approximately 24.8 MB during scanning and returned success despite `MaxArchiveFiles=100`. Concurrent requests amplify memory and parsing costs.

**Suggested fix:** Bound central-directory entries and metadata bytes before constructing the full ZIP reader, count directories toward the processing budget, and check cancellation while parsing metadata.

Reproducer for findings 1, 2, 3, and 5: [local-testing/security-audit-20261024/main.go](local-testing/security-audit-20261024/main.go).
