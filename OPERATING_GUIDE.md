# MilterGuard Operating Guide

Using the supplied default configuration, MilterGuard will initially monitor
inbound email and report how it would identify unwanted spam, scams, threats
concealed in images, and executable attachments without rejecting anything. It
will not scan authenticated outbound email. After enforcement is enabled, it
will provide basic virus protection by blocking executable attachments and will
learn and whitelist trusted email senders and identify and blacklist problematic
sending IP addresses to reduce false positives, false negatives, AI usage, and
operating costs.

**Need help?** For technical questions about MilterGuard, give ChatGPT or Claude
the repository URL, https://github.com/PhilAnderson1/MilterGuard, and ask it to
consult the current source code and documentation. Check any suggested
configuration changes before applying them to a live mail server.

For initial installation and activation, follow the
[MilterGuard Quick Start](QUICKSTART.md).

## Contents

1. [Configure the AI service](#configure-the-ai-service)
2. [Configure email authentication](#configure-email-authentication)
3. [Connect Postfix to MilterGuard](#connect-postfix-to-milterguard)
4. [Start MilterGuard in monitor mode](#start-milterguard-in-monitor-mode)
5. [Enable enforcement](#enable-enforcement)
6. [Basic virus protection](#basic-virus-protection)
7. [Rejection history and saved messages](#rejection-history-and-saved-messages)
8. [Trusted mail and adaptive filtering](#trusted-mail-and-adaptive-filtering)
9. [Administration commands](#administration-commands)
10. [Routine operation](#routine-operation)
11. [Replay saved email](#replay-saved-email)
12. [Remove MilterGuard](#remove-milterguard)

## Configure the AI service

MilterGuard's configuration file is `/etc/milterguard/milterguard.yaml`.
Edit it before starting the service, preserving its YAML indentation and using
spaces rather than tabs.

Running the AI model locally provides greater privacy, reliability, and
consistency, with no per-request API charges, so it is the recommended option.

### Running AI locally

The recommended Qwen3.6-35B-A3B model provides strong results with relatively
modest hardware requirements. A system with an 8 GB GPU, such as an RTX 4060,
and 32 GB of system RAM should work well with a suitable quantization and
configuration.

The model is available from:

https://huggingface.co/unsloth/Qwen3.6-35B-A3B-GGUF

Choose the largest quantization that fits comfortably within the available GPU
and system memory. Quantizations below 4-bit may reduce classification quality
and are not recommended. This practical guide explains how to run the model
efficiently with limited GPU memory:

https://piefed.crash.cx/c/localllama/p/123973/how-to-run-qwen-35b-a3b-on-4gb-to-8gb-of-vram-with-24-gb-system-ram

Serve the model through llama.cpp:

https://github.com/ggml-org/llama.cpp

Set MilterGuard's AI timeout high enough for the slowest messages and image
analysis, and keep the MTA's Milter timeout longer than the AI timeout. Start
with `ai.max_concurrent: 2`, then increase it only if the server can handle
additional requests without excessive memory use or response times.

Before using a local model on live mail, follow [Replay saved email](#replay-saved-email)
to check its classification accuracy and response time against representative
legitimate, spam, and scam messages.

### Hosted and other compatible services

To use OpenRouter instead, create an account and API key at
https://openrouter.ai. The supplied configuration already contains the necessary
OpenRouter settings; replace the placeholder `ai.api_key` with your key. If the
configured model is no longer available, select a current compatible model and
test it before enabling rejection.

MilterGuard also supports OpenAI and other llama.cpp-compatible endpoints. Set
`endpoint`, `endpoint_type`, `model`, and `api_key` to match the service. The
selected model must support image input if image analysis is enabled.

When using a hosted service, review its data-handling policy carefully.
MilterGuard sends the selected headers, extracted text, links, and qualifying
inline images used for classification. OpenRouter can restrict requests to
providers with a Zero Data Retention policy through its Privacy settings.

### Classification settings

Image analysis detects scams that conceal their message inside images. Set
`vision_mode` to `off`, `fallback` to inspect images when insufficient text is
available, or `always` to inspect them with every message. MilterGuard never
downloads remote images.

Before starting MilterGuard, review `/etc/milterguard/detection-prompt.txt` and
confirm that its rules match the email you want to reject. The supplied prompt
has been tested with the configured model; test any prompt or model changes in
monitor mode against representative legitimate and unwanted email before
enabling rejection.

## Configure email authentication

### Internal authentication (default)

The supplied configuration uses `authentication.mode: internal`, which is
recommended for new installations. MilterGuard calculates inbound SPF, DKIM,
and DMARC directly from the SMTP transaction and the byte-exact message. These
results are used only for MilterGuard's filtering, AI evidence, bypass, and
learning decisions. Existing `Authentication-Results` and `Received-SPF`
headers are ignored and delivered unchanged; MilterGuard neither validates nor
publishes authentication headers in this mode.

OpenDMARC and inbound OpenDKIM verification are not needed in this mode.
MilterGuard does not DKIM-sign outbound mail, so an existing OpenDKIM service
may still be used for outbound signing.

### Reuse existing authentication filters

If the server already has a complete, reliable local authentication stack, set
`authentication.mode: trusted_headers` to reuse its SPF, DKIM, and DMARC results.
This avoids repeating its DNS lookups and cryptographic verification.
MilterGuard must run after those filters and must trust only their locally
generated results. OpenDKIM alone normally supplies DKIM results, not the
complete SPF, DKIM, and DMARC evidence MilterGuard can use.

Add the authentication service identifiers written by the local filters to
`correspondents.trusted_authserv_ids`. The default `$mta_hostname` normally
matches results identified with the Postfix hostname. This setting is not used
in `internal` mode.

## Connect Postfix to MilterGuard

Add MilterGuard to `smtpd_milters` in `/etc/postfix/main.cf`. With internal
authentication and no other SMTP Milters:

```text
milter_default_action = accept
milter_protocol = 6
milter_content_timeout = 600s
smtpd_milters = inet:127.0.0.1:8895
```

If `smtpd_milters` already contains other filters, add MilterGuard at the end of
the list. For example, an OpenDKIM service on port 8891 may remain to sign
outbound mail:

```text
smtpd_milters = inet:127.0.0.1:8891, inet:127.0.0.1:8895
```

In `trusted_headers` mode, the local authentication filters must precede
MilterGuard. A typical complete chain is:

```text
OpenDKIM → OpenDMARC → MilterGuard
```

For example, with OpenDKIM on port 8891 and OpenDMARC on port 8892:

```text
smtpd_milters = inet:127.0.0.1:8891, inet:127.0.0.1:8892, inet:127.0.0.1:8895
```

Use the actual sockets or ports configured on the server. If
`non_smtpd_milters` is already configured, leave its existing filters in place
but do not add MilterGuard. MilterGuard should process SMTP mail only; applying
it to locally submitted system mail can reject legitimate notifications.

`milter_default_action = accept` keeps mail flowing if a Milter is unavailable.
Use `tempfail` instead if Postfix should defer delivery until every configured
Milter is available. `milter_content_timeout = 600s` gives bounded attachment
inspection and AI analysis time to complete. MilterGuard sends progress
responses during long AI operations so Postfix continues waiting.

### Filters that rewrite messages

Filters that only add their own diagnostic headers can normally remain in the
chain. Filters that rewrite sender or recipient headers, DKIM-signed headers,
MIME structure, or body content need special care. Postfix does not replay
changes requested by one Milter through the inspection callbacks of other
Milters, so changing their order does not guarantee that MilterGuard will
authenticate or analyse the final delivered representation.

If MilterGuard must evaluate exactly what will be delivered, disable that
rewrite for inbound mail or redesign the processing path so MilterGuard receives
the intended final representation. Review any deliberately retained rewrite to
ensure that its security consequences are understood.

### Protect authentication and result headers

In `trusted_headers` mode, Postfix must remove externally supplied
`Authentication-Results` and `Received-SPF` headers. A claimed authentication
service or receiver identifier does not prove that a header was created locally,
so otherwise a remote sender could forge evidence that MilterGuard trusts. Add
these rules to `/etc/postfix/header_checks`:

```text
/^Authentication-Results:/ IGNORE
/^Received-SPF:/ IGNORE
/^X-MilterGuard-(Classification|Score|Confidence|Action):/ IGNORE
```

Enable the table in `/etc/postfix/main.cf`, merging it with any existing
`header_checks` configuration:

```text
header_checks = regexp:/etc/postfix/header_checks
```

Postfix removes supplied authentication and MilterGuard result headers as it
receives the message. The local authentication filters can then add fresh
results before MilterGuard runs. Do not apply these rules through
`milter_header_checks`, which operates on headers added by Milters.

In `internal` mode, these authentication-header rules are not required by
MilterGuard. It ignores `Authentication-Results` and `Received-SPF` when making
its decisions and leaves them unchanged for other mail-system components. It
does not endorse those headers or publish its own calculated results.
Authenticated SMTP submissions also leave them unchanged. The
`X-MilterGuard-...` rule may still be kept to prevent a sender from supplying
misleading MilterGuard result headers.

### Required Postfix connection data

Internal SPF verification requires Postfix to supply its `{daemon_addr}`
connect macro. Postfix 3.2 and later include it in the default
`milter_connect_macros`; installations with a customized list must retain it.

MilterGuard supplies the connecting IP, reported hostname, HELO/EHLO identity,
reverse DNS, and forward-confirmation result to the AI as supporting evidence.
DNS failures do not reject or defer mail, and lookup time is bounded by
`milter.connection_dns_timeout`.

Postfix must supply the authenticated user's SASL identity so MilterGuard can
recognize outbound mail, learn trusted correspondents, and authorize email
commands. Without it, mail can still be scanned, but those authenticated-user
features do not operate.

Ensure `{auth_authen}` is present in Postfix's `milter_mail_macros`. Check the
effective values before changing them:

```sh
postconf myhostname milter_protocol milter_content_timeout milter_connect_macros milter_mail_macros smtpd_milters non_smtpd_milters
```

For full MilterGuard functionality, the output should have these
characteristics:

```text
myhostname = mail.example.com
milter_protocol = 6
milter_content_timeout = 600s
milter_connect_macros = ... j ... {daemon_addr} ...
milter_mail_macros = ... {auth_authen} ...
smtpd_milters = ...existing filters..., inet:127.0.0.1:8895
```

The hostname and any existing filter sockets will be specific to the server.
Internal mode requires valid `j` and `{daemon_addr}` connect macros;
`{auth_authen}` must appear in `milter_mail_macros`. MilterGuard must be last in
`smtpd_milters`. If `non_smtpd_milters` appears in the output, it must not
contain MilterGuard.

### Advanced authentication and listener settings

Loopback TCP listeners are usually simplest when several Milter services are in
use. Unix sockets also work, but their directory ownership, permissions, and any
Postfix chroot must be configured correctly. If a Unix socket is shared through
a group, limit membership to Postfix, MilterGuard, and other explicitly trusted
mail-filter processes. Every process able to connect is trusted to act as the
MTA.

MilterGuard trusts connection details and authentication data supplied through
its listener, so only Postfix should be able to connect. The supplied
`milter.allowed_peer_ips` setting permits loopback connections only. If Postfix
runs on another machine, add only that server's address or a tightly scoped CIDR
and restrict the Milter port with a firewall. Unix listeners rely on directory
and socket permissions instead.

`milter.max_connections` bounds the number of messages MilterGuard can hold at
once, including messages waiting for an AI analysis slot. The supplied value of
`64` provides headroom above `ai.max_concurrent: 8` while limiting aggregate
memory use. Memory-constrained systems may use a lower value, but should retain
enough headroom above AI concurrency for normal mail bursts. Increasing AI
concurrency helps only when the configured service can process the additional
requests efficiently; locally hosted AI commonly needs a lower value.

`authentication.message_storage` controls how the byte-exact message is kept
until verification completes. The default `memory` mode is fastest. Its
theoretical additional memory bound is approximately
`milter.max_connections × milter.max_message_size`, although normal messages
are smaller and the buffer is released immediately after authentication. Use
`file` when large message limits or high concurrency make that bound unsuitable.
File mode creates a mode-0600 temporary file, unlinks it immediately, and keeps
only its descriptor until verification completes.

`authentication.timeout` bounds queueing plus SPF, DKIM, and DMARC work for one
message. `authentication.max_concurrent` bounds simultaneous verification
operations. Both values must be positive.

### Optional early rejection with Spamhaus ZEN

Spamhaus ZEN can reject mail from known abusive sending IP addresses before
MilterGuard receives the message body or starts AI analysis. This reduces mail
processing and API usage while complementing, rather than replacing,
MilterGuard's content analysis.

Configure the check in Postfix so trusted networks and authenticated submission
clients bypass it. Ensure that your use complies with the
[Spamhaus usage terms](https://www.spamhaus.com/terms-of-use-fair-use-policy-for-free-data-query-service/)
and follow the current
[Spamhaus DNSBL guidance](https://www.spamhaus.org/faqs/dnsbl-usage/).
Do not query the public Spamhaus service through a public DNS resolver such as
`1.1.1.1` or `8.8.8.8`; use a suitable local resolver or Spamhaus DQS.

After changing `main.cf`, check and reload Postfix:

```sh
sudo postfix check
sudo postfix reload
```

## Start MilterGuard in monitor mode

The default `monitor` mode analyses email and logs the action MilterGuard
would recommend, but allows the message through. Leave it in this mode while you
send representative test messages and observe real mail traffic. Monitor mode
does not update correspondent allowlists or IP reputation.

Review the journal regularly:

```sh
journalctl -u milterguard --since yesterday --no-pager -o cat
```

Pay particular attention to legitimate messages classified as unwanted,
unwanted messages classified as legitimate, endpoint failures, and unusually
slow responses. Adjust the detection prompt, model, or rejection threshold when
the results consistently show that a change is needed.

## Enable enforcement

When monitor-mode results are satisfactory, change the mode to `enforce` and
restart MilterGuard. It will then reject unwanted messages that meet the
configured confidence threshold and block prohibited executable attachments.

The supplied configuration sets `filtering.ai_error_action: accept`. If AI
analysis fails, MilterGuard therefore delivers the message without an AI
classification rather than delaying legitimate mail during an endpoint outage.
When `filtering.add_email_headers` is enabled, the accepted message is marked
with `X-MilterGuard-Classification: unavailable` and
`X-MilterGuard-Action: accepted-ai-error`. Set
`filtering.ai_error_action: tempfail` instead if the sending server should
retain the message and retry after the AI service becomes available.

### Deterministic acceptances without AI analysis

MilterGuard accepts some trusted messages without sending them to the AI
endpoint:

- Authenticated SMTP submissions bypass AI analysis when
  `filtering.scan_authenticated` is `false`, as it is in the supplied
  configuration so that outbound emails can bypass scanning.
- A sender in the contacts whitelist can be accepted without AI analysis when
  the configured authentication requirements are met.
- A visible `From:` domain in the trusted sender-domain allowlist can bypass AI
  analysis when its configured authentication requirements—normally trusted,
  aligned DKIM—are met.

See [Trusted mail and adaptive filtering](#trusted-mail-and-adaptive-filtering)
for how MilterGuard learns and verifies correspondents and configures trusted
sender domains.

### Deterministic rejections without AI analysis

In `enforce` mode, MilterGuard can also reject some messages without sending
them to the AI endpoint:

- An active IP reputation block rejects the SMTP transaction at `MAIL FROM`,
  before MilterGuard receives the body. Because the complete message is not
  available, this rejection cannot be added to rejection history or the saved
  message archive. Administrators can list, add, and remove these IP blocks
  through the [administration command interfaces](#administration-commands).
- To prevent outsiders from impersonating your own domains, list domains for
  which this server is the only legitimate mail source under
  `filtering.authenticated_only_sender_domains`. MilterGuard then rejects
  unauthenticated messages using those domains—or their subdomains—in the
  visible `From:` address, records and archives the rejection, and adds a strike
  against the sending IP. Do not list a domain if this is not its only valid
  mail server, for example if your organisation operates multiple mail servers
  or a legitimate third party sends email on its behalf.
- Attachment and MIME policies can reject prohibited executable, encrypted,
  unscannable, or malformed content. See
  [Basic virus protection](#basic-virus-protection) for the supported formats
  and configuration choices.

The above checks take place before AI analysis.

Alternatively, setting `mode: tag` accepts all mail while adding result
headers. Successfully analysed mail includes its classification and score.
Attachment policy and IP reputation do not reject mail in tag mode, and adaptive
correspondent and IP reputation data is not changed.

### Deliver tagged mail to the Junk folder

MilterGuard's result headers can be used by a server-side delivery filter or
mail client to move flagged messages into a Junk or Spam folder. For example,
this Dovecot Sieve rule moves every message classified as unwanted:

```sieve
require ["fileinto"];

if header :is "X-MilterGuard-Classification" "unwanted" {
    fileinto "Junk";
    stop;
}
```

This is particularly useful with `mode: tag`, where MilterGuard accepts all
mail and leaves the final delivery decision to another filter. To move only
lower-confidence unwanted classifications, use:

```sieve
require ["fileinto"];

if allof (
    header :is "X-MilterGuard-Classification" "unwanted",
    header :is "X-MilterGuard-Confidence" "low"
) {
    fileinto "Junk";
    stop;
}
```

In `enforce` mode, unwanted messages at or above `reject_score` are rejected;
the rule above handles unwanted messages accepted because their score is below
that threshold. To review low-confidence legitimate classifications as well,
use a corresponding rule:

```sieve
if allof (
    header :is "X-MilterGuard-Classification" "legitimate",
    header :is "X-MilterGuard-Confidence" "low"
) {
    fileinto "Junk";
    stop;
}
```

Set `filtering.add_email_headers` to `true` unless using `mode: tag`, which
always adds result headers. Adjust `Junk` if your destination mailbox has a
different name. Equivalent rules can be configured in a mail client instead of
Sieve. Do not trust these headers downstream unless Postfix removes forged
incoming `X-MilterGuard-*` headers or MilterGuard has removed them using the
Milter change-header capability, as described earlier in this guide.

Continue reviewing decisions after enabling enforcement. AI classification is
not perfectly deterministic, and changes made by an AI provider can alter a
model's behaviour even when the configured model name remains unchanged.

## Basic virus protection

MilterGuard provides basic virus protection by rejecting executable
attachments before AI analysis. It checks configured filename extensions and
recognizes Windows PE, Linux ELF, Mach-O, and executable script signatures, so
simply renaming an executable does not conceal it. This is deliberately narrower
than a full antivirus engine and does not identify every form of malicious
document or exploit.

ZIP, TAR, GZIP, and BZIP2 archives are inspected in memory without extracting
files onto disk. The supplied configuration also blocks 7z and RAR attachments
because MilterGuard cannot inspect their contents. Attachment size, archive
depth, file-count, and total uncompressed-size limits protect the service from
oversized files and archive bombs.

The `attachments` configuration controls what happens when an archive is
encrypted or content cannot be completely inspected. Each condition may be
accepted, rejected, or temporarily deferred with `tempfail`. In the supplied
configuration, encrypted archives are rejected while other unscannable content
is accepted and continues to AI analysis. The separate `invalid_mime_action`
setting controls permanently invalid or ambiguous MIME structure; it defaults
to rejection because retrying cannot repair the message. Monitor mode records
the proposed attachment action but still accepts the message.

## Rejection history and saved messages

The `rejection_history` configuration records the sender address, envelope
recipients, rejection time, subject, and reason for messages rejected by AI,
attachment or MIME inspection, or the authenticated-only sender-domain policy
in enforce mode. It can also save the corresponding original message as an
`.eml` file when `save_messages` is enabled. Copies are organized beneath
`message_directory` as `YYYY/MM/DD`, with the rejection ID as the filename.
Cached IP rejections happen before the email is received and therefore cannot
be recorded or saved.

The archive may contain private correspondence and dangerous attachments, so
restrict access to it. Retention cleanup runs at startup and every 24 hours;
expired date directories are removed hierarchically. If the archive exceeds its
`message_max_total_bytes` target size, daily cleanup removes the oldest retained
messages until it is below the target. `rejection_history.expiry` controls both
the database record and saved-message lifetime, keeping the two parts aligned.
Archive errors are logged but never alter the SMTP filtering decision.

The rejection database may temporarily exceed its `max_entries` target between
maintenance runs; expired and excess oldest entries are then removed
automatically. Setting `rejection_history.expiry` to `0s` disables the history
and requires `save_messages` to be disabled as well.

## Trusted mail and adaptive filtering

Authenticated outbound mail is not scanned by default. MilterGuard uses
accepted outbound mail to learn which external addresses each local user
corresponds with. These addresses are immediately whitelisted and can bypass
future scanning when the configured authentication requirements are met.
Authenticated submission client addresses are never blocked or otherwise
modified by IP reputation, even when authenticated mail scanning is enabled.
MilterGuard can also learn inbound senders that repeatedly receive a
high-confidence legitimate classification and pass the configured authentication
checks.

This reduces cost and avoids repeatedly classifying routine mail. Entire email
domains can also be whitelisted in the configured trusted-sender domains file.
The supplied file contains a curated low-risk sender list whose messages bypass
scanning only when trusted, aligned DKIM authentication passes. Merely forging
an address in one of these domains therefore does not bypass filtering.

For visible `From:` domains supported by a trusted DKIM, SPF, or DMARC pass, the
optional `domain_registration` feature obtains the registrable domain's creation
and expiry dates through RDAP and supplies its age to the AI as supporting
evidence.
An uncached lookup sends the sender's registrable domain name to an external
RDAP service, but not the email address or message content. Set
`domain_registration.enabled: false` to disable these lookups.
Results are cached locally; expired entries are refreshed only if the domain is
seen again, and entries more than two weeks past expiry are removed. Lookup
failures never reject or defer mail.

When MilterGuard rejects unwanted mail, it records the sending IP address.
Repeated attempts can then be rejected without another AI request, and persistent
offenders receive longer blocks. Legitimate traffic gradually reduces an IP's
negative reputation. In the supplied configuration, every three legitimate
messages removes one recorded unwanted-mail strike, although an active block
continues until it expires. Configured shared mail providers are protected from
automatic blacklisting.

The `ip_reputation.ip_allowlist` prevents trusted IP addresses and networks from
ever being blacklisted. The `domain_allowlist` provides the same protection for
sending hosts whose reverse-DNS hostname matches a listed domain or subdomain,
but only after the hostname has been forward-resolved back to the connecting IP.
This protects shared mail providers without allowing a forged PTR record to
bypass reputation handling.

## Administration commands

### Command line

MilterGuard provides an interactive administrator interface for managing
allowlists, IP blocks, and rejection history:

```sh
sudo milterguard --command-mode
```

If MilterGuard uses a non-default configuration file, specify it explicitly:

```sh
sudo milterguard --config /path/to/milterguard.yaml --command-mode
```

Command mode permits administrative operations on the live database, so the
MilterGuard service does not need to be stopped.
Use the Up and Down arrow keys to revisit commands from the current session;
history is not saved to disk.

Available commands are:

```text
WHITELIST ADD sender@example.com recipient@example.com
WHITELIST DELETE sender@example.com [recipient@example.com|*]
WHITELIST LIST [recipient@example.com|*] [day|week|month|year|all]
REJECTIONS [recipient@example.com|*] [day|week|month|year|all]
REJECTION id
IP LIST [day|week|month|year|all]
IP LIST LOOKUP [day|week|month|year|all]
IP ADD 192.0.2.1
IP DELETE 192.0.2.1
HELP
EXIT
```

- `WHITELIST ADD`, `WHITELIST DELETE`, and `WHITELIST LIST` manage trusted
  correspondent addresses.
- `REJECTIONS` lists rejected messages, including their rejection IDs and
  reasons.
- `REJECTION <id>` displays the rejection information for the rejected email
  with ID `<id>` and its decoded, cleaned plain-text body.
- `IP LIST` shows active short and repeat-offender blocks. `IP LIST LOOKUP`
  also performs reverse-DNS lookups and includes each hostname or `(not found)`.
- `IP ADD` creates a manual block using the configured repeat-offender duration,
  or the short duration when repeat-offender blocking is disabled. `IP DELETE`
  removes the IP reputation record.
- `HELP` displays the command summary. `EXIT`, `QUIT`, or Ctrl-D closes the
  session.

Listing commands default to all local recipients and the previous week.
`day`, `week`, `month`, and `year` select activity since the corresponding
point in the past; `all` removes that additional date filter while retaining
configured expiry rules. Whitelist and active-IP listings use last activity;
rejection history uses rejection time. Interactive lists are printed from
oldest to newest so the latest entries appear immediately above the prompt.
Each listing returns at most 1,000 matching records and reports when that limit
has been reached; use a shorter date period or a recipient filter to narrow a
large result.

`REJECTION <id>` displays the rejection information and processed body. When
the original saved message is available, command mode reports its full archive
path and size. The processed body is regenerated with the current MIME and HTML
parser, so it may differ from the text originally supplied to the AI. Connection
and authentication analysis is not reconstructed.

For bulk additions or deletions to the contact or IP databases, commands can
also be read from a file or pipeline:

```sh
sudo milterguard --command-mode < commands.txt
```

### Email commands

The optional email command interface supports the same commands and sends the
results back by email. For ordinary authenticated users, the local recipient
address is inferred from the authenticated envelope sender, so it is omitted
from `WHITELIST` and `REJECTIONS` commands. Administrators may specify another
recipient or use `*`, and may use the IP commands.

Enable and configure `email_commands` in
`/etc/milterguard/milterguard.yaml`. Set `recipient` to the local command
address, replacing `example.com` with a domain received by your server:

```yaml
email_commands:
  enabled: true
  recipient: milterguard@example.com
```

Add the following entry to `/etc/aliases`, then run `newaliases`:

```text
milterguard: /dev/null
```

To enable an administrator, add their SASL login name to `administrators` in
the `email_commands` configuration. Administrators can manage or inspect any
local recipient and use `*` to select all recipients. Leave
`allow_authenticated_users` set to `false` if only administrators should be
able to issue commands.

To also permit normal local users to access commands relevant to their email
address only, set `allow_authenticated_users` to `true`. MilterGuard must
verify that the envelope-sender address belongs
to the authenticated SASL user. With `verify_sender_via_aliases` set to `true`,
it performs this verification using `/etc/aliases`. If alias verification is
disabled, you must configure Postfix to enforce sender ownership instead. For
example, create `/etc/postfix/sender_login_maps` containing:

```text
phil.anderson@example.com philip
alias@example.com         philip
```

Then run `sudo postmap /etc/postfix/sender_login_maps` and merge these settings
into `/etc/postfix/main.cf`:

```text
smtpd_sender_login_maps = hash:/etc/postfix/sender_login_maps
smtpd_sender_restrictions = reject_authenticated_sender_login_mismatch
```

Place the restriction before any rule broadly permitting authenticated clients.
Without alias verification or Postfix sender ownership enforcement, an
authenticated user could impersonate another local address and manage its
MilterGuard data. Check and reload Postfix after making changes:

```sh
sudo postfix check
sudo postfix reload
```

Send the command email to the configured address as its sole recipient, with
one command on each line. Commands run in order, and one reply contains all
results. Processing stops at the first unrecognized line, allowing quoted text
or a signature to follow. Listing results are newest-first and default to the
previous week.

`REJECTION <id>` is restricted to messages addressed to the requesting user;
administrators may retrieve any record. Its reply contains the rejection reason
and processed body and, when available, attaches the original message as
`rejection-<id>.eml`.

Replies are submitted through `email_commands.smtp_host`, which defaults to
`127.0.0.1:25`. `email_commands.smtp_tls` controls transport encryption:
`off` never attempts STARTTLS, `opportunistic` uses STARTTLS when a non-loopback
server advertises it, and `required` refuses to send unless STARTTLS with a
valid server certificate can be established. An advertised STARTTLS service
that fails negotiation or certificate verification is never downgraded to
plaintext. Replies can contain allowlist and rejection-history data, so use
`required` with remote SMTP servers where possible. SMTP authentication is not
currently supported.

## Routine operation

Keep the service, detection prompt, and model under review as the mail you receive
changes. Check the journal for rejected mail, endpoint errors, attachment-policy
decisions, and changes in classification quality. After changing the prompt,
model, confidence threshold, or filtering policy, repeat the
[mailbox replay tests](#replay-saved-email) before restarting production.

Invalid API credentials and insufficient API credit are logged as distinct
error-level events with `endpoint_error_kind` and `endpoint_status_code` fields,
making them suitable for journal monitoring and alerts.

The result headers described under
[Deliver tagged mail to the Junk folder](#deliver-tagged-mail-to-the-junk-folder)
are safe to use only after forged incoming copies have been removed. MilterGuard
does this when Postfix offers Milter change-header support; in `trusted_headers`
mode, the recommended Postfix `header_checks` rule also removes them at the SMTP
boundary.

Review `/etc/milterguard/trusted-sender-domains.txt` periodically and remove
domains that no longer represent low-risk, organization-controlled senders. Add
new domains conservatively because matching, authenticated mail bypasses AI
analysis. List one lowercase, exact domain per line; wildcards are not accepted.
An entry such as `amazon.com` also matches its subdomains, but regional domains
such as `amazon.co.uk` and `amazon.de` must be listed separately. With
`sender_domain_allowlist_require_dkim` enabled, a matching domain bypasses AI
only when MilterGuard receives a trusted, aligned DKIM pass. Restart
MilterGuard after changing the file.

If the trusted-domain file is missing, empty, or unreadable, MilterGuard logs a
warning and continues with trusted-domain bypass disabled.

Keep `logging.include_ai_input` disabled during normal operation. Enabling it
writes the complete textual AI input - including message content, links, and
personal data - to the system journal. Use it only temporarily for diagnostics;
inline image bytes are not logged.

Successful decision logs include the email subject when
`logging.include_subject` is `true`, as it is in the supplied configuration.
Subjects may contain personal or sensitive information; set this option to
`false` if they should not be written to the system journal. Set
`logging.include_connections` to `true` only when connection-open and
connection-close debug messages are useful for troubleshooting.

### Data storage and maintenance

Learned correspondents, rejection history, IP reputation, and cached domain
registration data are stored in `/var/lib/milterguard/milterguard.db`. Stop
MilterGuard before copying this SQLite database so the backup is complete and
consistent. Back it up when moving the learned state to another machine.

Changes are committed immediately. `persistence.cleanup_interval` controls the
periodic removal of expired and excess records and must be at least one minute;
cleanup also runs at startup and checkpoints SQLite's write-ahead log. Expired
domain-registration entries are ignored during lookups even before cleanup
removes them.

Validate configuration changes and test the configured AI endpoint before
applying them:

```sh
milterguard --config /etc/milterguard/milterguard.yaml \
  --check-config --check-endpoint
```

The endpoint check sends one synthetic test email through the configured model
and detection prompt. Success is reported as `configuration is valid` followed
by `Endpoint OK`.

Before starting MilterGuard for the first time, add `--check-port` to confirm
that its configured Milter listener is available. Run this check only while
MilterGuard is stopped; a running instance already occupies its listener and
will correctly cause the check to fail.

## Replay saved email

Mailbox replay lets you test a MilterGuard configuration, AI model, and
detection prompt against a corpus of saved `.eml` files with known expected
outcomes. Use it before enabling enforcement or deploying changes to identify
false positives, missed spam, inconsistent classifications, and excessive
response times without processing the messages as live mail.

The release includes `tools/replay_mailbox.py`, which requires Python 3 and
submits every `.eml` file in a directory directly to a test MilterGuard
instance.

Run a separate test instance of MilterGuard in `enforce` mode on an unused port.
Give its configuration a separate `persistence.database_file` so testing cannot
alter production correspondent, rejection-history, or IP-reputation data. To
ensure every corpus message reaches the AI, set `ip_reputation.block_duration`
to `0s`, `ip_reputation.repeat_threshold` to `0`, and
`correspondents.use_allowlist` to `false` in the test configuration. The replay
tool reports the actual Milter response rather than only the AI classification.
A test instance in `monitor` mode will therefore report every message as
accepted even when MilterGuard recommends rejection. In `enforce` mode, a
message classified as unwanted will still be reported as accepted when its
score is below the rejection threshold defined in the configuration file.

By default, the replay tool reconstructs the SMTP peer IP, client hostname,
HELO identity, and receiving MTA hostname from the saved `Received` headers. It
also derives the envelope sender and recipient from `Return-Path`,
`X-Original-To`, `Delivered-To`, or the visible address headers. Each message
uses a separate Milter connection.

In `internal` authentication mode, MilterGuard ignores saved authentication
results and recalculates SPF, DKIM, and DMARC from the reconstructed SMTP data,
the byte-preserved message, and current DNS records. Supply `--receiver-ip` with
the address of the receiving MTA so the required `{daemon_addr}` macro is
available. Results can differ from those obtained when the message originally
arrived if SMTP details are missing or DNS records and DKIM keys have changed.

In `trusted_headers` mode, the reconstructed MTA hostname allows saved local
authentication results with a trusted authentication-service identifier to be
used. Use this mode only with messages captured from a server whose result
headers you trust. Use `--connection-info synthetic` for a deterministic
loopback identity, or the individual override options shown by `--help`.

Test representative directories and save the JSON Lines results using the
installed mailbox replay script. First set `REPLAY_SCRIPT` to the appropriate
path for the installation method.

For a `.deb` or `.rpm` installation:

```sh
REPLAY_SCRIPT=/usr/share/milterguard/tools/replay_mailbox.py
```

For a `.tar.gz` installation:

```sh
REPLAY_SCRIPT=/usr/local/share/milterguard/tools/replay_mailbox.py
```

Then run the required tests:

Replace the example `--receiver-ip` value with the address on which the mail
server received the original messages.

```sh
python3 "$REPLAY_SCRIPT" \
  /path/to/legitimate --host 127.0.0.1 --port 8894 \
  --receiver-ip 203.0.113.25 --expected accept \
  | tee legitimate-results.jsonl

python3 "$REPLAY_SCRIPT" \
  /path/to/spam --host 127.0.0.1 --port 8894 \
  --receiver-ip 203.0.113.25 --expected reject \
  | tee spam-results.jsonl

python3 "$REPLAY_SCRIPT" \
  /path/to/scam --host 127.0.0.1 --port 8894 \
  --receiver-ip 203.0.113.25 --expected reject \
  | tee scam-results.jsonl
```

Port 8894 is used above for the separate test instance of MilterGuard.

Add `--dots-on-match` to show one dot per expected result while keeping full
details for mismatches and errors. The final summary is always printed. Omit
this option when saving JSON Lines output for later processing.

Each line records the file, result, expected result, whether they matched,
latency, SMTP rejection detail, reconstructed connection information, and the
envelope addresses used. The final line summarizes the run.

## Remove MilterGuard

Back up `/etc/milterguard` and `/var/lib/milterguard` before removal if their
configuration, learned state, rejection history, or archived messages may be
needed again.

Before uninstalling MilterGuard, remove its socket from `smtpd_milters` in
`/etc/postfix/main.cf`, then check and reload Postfix:

```sh
sudo postfix check
sudo postfix reload
```

Leaving the removed Milter in Postfix's chain can defer mail when
`milter_default_action` is `tempfail`, or cause repeated connection errors when
it is `accept`.

On Debian and Ubuntu, remove the software while preserving its configuration,
data, and service account with:

```sh
sudo apt remove milterguard
```

To remove the software, configuration, data, and service account permanently,
use:

```sh
sudo apt purge milterguard
```

RPM has no separate purge operation. On Red Hat-based systems, including
AlmaLinux, remove the packaged software while preserving generated state under
`/var/lib/milterguard` and the service account with:

```sh
sudo dnf remove milterguard
```

RPM may retain modified configuration as `.rpmsave` files. To remove all
remaining configuration, state, and the service account after `dnf remove`,
inspect any retained files and then run:

```sh
sudo rm -rf /etc/milterguard /var/lib/milterguard
sudo userdel milterguard
sudo groupdel milterguard
```

For a portable `.tar.gz` installation, enter the extracted release directory
and run:

```sh
sudo ./uninstall.sh
```

The portable uninstaller displays the files and data it will delete, requires
explicit confirmation, and then asks whether to remove the service account.
