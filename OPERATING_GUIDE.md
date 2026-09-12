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
2. [Install and configure OpenDKIM and OpenDMARC (optional)](#install-and-configure-opendkim-and-opendmarc-optional)
3. [Connect MilterGuard to Postfix](#connect-milterguard-to-postfix)
4. [Start in monitor mode](#start-in-monitor-mode)
5. [Enable enforcement](#enable-enforcement)
6. [Basic virus protection](#basic-virus-protection)
7. [Rejected message archive](#rejected-message-archive)
8. [Trusted mail and adaptive filtering](#trusted-mail-and-adaptive-filtering)
9. [Email commands](#email-commands)
10. [Running AI locally](#running-ai-locally)
11. [Routine operation](#routine-operation)
12. [Replay saved email](#replay-saved-email)

## Configure the AI service

MilterGuard's configuration file is `/etc/milterguard/milterguard.yaml`.
Edit it before starting the service, preserving its YAML indentation and using
spaces rather than tabs.

Running the AI model locally provides greater privacy, reliability and
consistency, with no per-request API charges, so it is the recommended option.
The recommended model has relatively modest hardware requirements and can
perform well with a suitable GPU. See Running AI locally for setup guidance.

To use OpenRouter instead, create an account and API key at
https://openrouter.ai. Using the recommended model typically costs around
US$0.35 per 1,000 scanned emails, although the actual cost varies with message
length and provider pricing. The supplied configuration already contains the
necessary OpenRouter settings; replace the placeholder `ai.api_key` with your
key. If the configured model is no longer available, select a current compatible
model and test it before enabling rejection.

MilterGuard sends the email data used for classification to the configured AI
endpoint, including selected headers, extracted text, links, and qualifying
inline images. When using a hosted service, review its data-handling policy
carefully. OpenRouter can restrict requests to providers with a Zero Data
Retention policy through its Privacy settings.

MilterGuard supports OpenRouter, OpenAI, and llama.cpp-compatible endpoints.
Set `endpoint`, `endpoint_type`, `model`, and `api_key` to match the service.
The selected model must support image input if image analysis is enabled.

Image analysis detects scams that conceal their message inside images. Set
`vision_mode` to `off`, `fallback` to inspect images when insufficient text is
available, or `always` to inspect them with every message. MilterGuard never
downloads remote images.

Before starting MilterGuard, review `/etc/milterguard/detection-prompt.txt` and
confirm that its rules match the email you want to reject. The supplied prompt
has been tested with the configured model; test any prompt or model changes in
monitor mode against representative legitimate and unwanted email before
enabling rejection.

## Install and configure OpenDKIM and OpenDMARC (optional)

MilterGuard works without OpenDKIM or OpenDMARC, but trusted DKIM, SPF, and
DMARC results give the AI stronger evidence about sender identity and improve
classification quality. Without trusted DKIM results, trusted-domain bypass,
authenticated correspondent bypass, and automatic sender learning are less
effective or unavailable.

Your server may already use OpenDKIM to sign outbound email. If so, configure
it to verify inbound signatures and add its results to `Authentication-Results`.
OpenDMARC can then evaluate DMARC and SPF and add those results for MilterGuard
to use. Install the packages supplied by your operating system and configure
each service to expose a Milter socket or local TCP listener to Postfix.
Loopback TCP listeners are generally simpler to configure consistently across
multiple Milter services. Unix sockets also work, but their directory ownership,
permissions, and any Postfix chroot must be configured correctly.
If a Unix socket is shared through a group, keep that group limited to Postfix,
MilterGuard, and any other explicitly trusted mail-filter processes. Every
member able to connect to the socket is trusted to act as the MTA.

MilterGuard trusts connection details and authentication data supplied through
its Milter listener, so only Postfix must be able to connect. The supplied
`milter.allowed_peer_ips` setting permits loopback connections only. If Postfix
runs on another machine, add only that server's address (or a tightly scoped
CIDR) and restrict the Milter port with a firewall. Unix listeners rely on their
directory and socket permissions instead.

These filters must run in this order:

```text
OpenDKIM → OpenDMARC → MilterGuard
```

The authentication service identifier written to `Authentication-Results`
must be included in MilterGuard's `correspondents.trusted_authserv_ids` setting.
The supplied `$mta_hostname` value normally handles results identified with the
Postfix hostname.

Before relying on those results, configure Postfix to remove externally
supplied `Authentication-Results` headers. Their authentication service
identifier is not proof that they were created locally, so without this step a
remote sender could forge evidence that MilterGuard trusts. Add the following
rule to `/etc/postfix/header_checks`:

```text
/^Authentication-Results:/ IGNORE
/^X-MilterGuard-(Classification|Score|Confidence|Action):/ IGNORE
```

Enable the table in `/etc/postfix/main.cf`, merging it with any existing
`header_checks` configuration:

```text
header_checks = regexp:/etc/postfix/header_checks
```

Postfix removes the supplied authentication and MilterGuard result headers as
it receives the message. OpenDKIM and OpenDMARC then add freshly calculated
authentication results before MilterGuard runs, and MilterGuard may add its own
result headers. Do not apply these removal rules through `milter_header_checks`,
which operates on headers added by Milters.

## Connect MilterGuard to Postfix

Add MilterGuard to the end of each applicable Milter list in
`/etc/postfix/main.cf`. Postfix calls Milters in the configured order, allowing
MilterGuard to use authentication results added by earlier filters.

With no authentication filters:

```text
milter_default_action = accept
milter_protocol = 6
smtpd_milters = inet:127.0.0.1:8895
non_smtpd_milters = inet:127.0.0.1:8895
```

With OpenDKIM listening on port 8891:

```text
milter_default_action = accept
milter_protocol = 6
smtpd_milters = inet:127.0.0.1:8891, inet:127.0.0.1:8895
non_smtpd_milters = inet:127.0.0.1:8891, inet:127.0.0.1:8895
```

With OpenDKIM on port 8891 and OpenDMARC on port 8892:

```text
milter_default_action = accept
milter_protocol = 6
smtpd_milters = inet:127.0.0.1:8891, inet:127.0.0.1:8892, inet:127.0.0.1:8895
non_smtpd_milters = inet:127.0.0.1:8891, inet:127.0.0.1:8892, inet:127.0.0.1:8895
```

Use the actual sockets or ports configured for your services. MilterGuard must
remain last in the chain.

MilterGuard also supplies the connecting IP, reported hostname, HELO/EHLO
identity, reverse DNS, and forward-confirmation result to the AI as supporting
evidence. DNS failures do not reject or defer mail, and lookup time is bounded
by `milter.connection_dns_timeout`.

`smtpd_milters` processes mail received over SMTP. `non_smtpd_milters` processes
locally submitted mail, including messages submitted through Postfix's
`sendmail` command. Omit MilterGuard from `non_smtpd_milters` if that mail
must not pass through it.

Postfix must supply the authenticated user's SASL identity so MilterGuard can
recognize outbound mail, learn trusted correspondents, and authorize email
commands. Without it, mail can still be scanned, but these authenticated-user
features will not operate.

Ensure `{auth_authen}` is present in Postfix's `milter_mail_macros` setting so
MilterGuard can recognize SASL-authenticated mail. Check the effective values
before changing them:

```sh
postconf myhostname milter_protocol milter_mail_macros smtpd_milters non_smtpd_milters
```

For full MilterGuard functionality, the output should have these
characteristics:

```text
myhostname = mail.example.com
milter_protocol = 6
milter_mail_macros = ... {auth_authen} ...
smtpd_milters = ...authentication filters..., inet:127.0.0.1:8895
non_smtpd_milters = ...authentication filters..., inet:127.0.0.1:8895
```

The hostname and authentication-filter sockets will be specific to the mail
server. `{auth_authen}` must appear in `milter_mail_macros`, and MilterGuard
must be the last entry in each Milter list in which it is enabled. It is valid
to omit MilterGuard from `non_smtpd_milters` when locally submitted mail does
not need scanning.

MilterGuard can process allowlist and reporting commands received by email.
When ordinary authenticated users may use this feature and
`email_commands.verify_sender_via_aliases` is `true`, MilterGuard uses
`/etc/aliases` to verify that the authenticated envelope-sender address belongs
to the SASL user. If ordinary users are allowed and alias verification is
disabled, configure Postfix to enforce envelope-sender ownership. For a hash
table, create
`/etc/postfix/sender_login_maps` with one address and its permitted SASL login
per line:

```text
phil.anderson@example.com philip
alias@example.com         philip
```

Build the lookup table and add the ownership check to `main.cf`:

```sh
sudo postmap /etc/postfix/sender_login_maps
```

```text
smtpd_sender_login_maps = hash:/etc/postfix/sender_login_maps
smtpd_sender_restrictions = reject_authenticated_sender_login_mismatch
```

Merge the restriction into any existing `smtpd_sender_restrictions` instead of
replacing them, and place it before a rule that broadly permits authenticated
clients. Every envelope-sender address an authenticated user needs must appear
in the map. Otherwise Postfix will reject that user when they send from the
unlisted address. Without alias verification or Postfix sender-login
enforcement, an authenticated user could impersonate another local address and
manage its MilterGuard data.

After changing `main.cf`, check and reload Postfix:

```sh
sudo postfix check
sudo postfix reload
```

## Start in monitor mode

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

Alternatively, setting `mode: tag` accepts all mail while adding result
headers. Successfully analysed mail includes its classification and score.
Attachment policy and IP reputation do not reject mail in tag mode, and adaptive
correspondent and IP reputation data is not changed.

Continue reviewing decisions after enabling enforcement. AI classification is
not perfectly deterministic, and changes made by an AI provider can alter a
model's behaviour even when the configured model name remains unchanged.

The supplied configuration accepts mail if AI analysis fails. This avoids mail
loss when the endpoint is unavailable. If you prefer the sending server to try
again later, change the configured AI failure action to `tempfail`.

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
is accepted and continues to AI analysis. Monitor mode records the proposed
attachment action but still accepts the message.

## Rejected message archive

The optional `rejected_mail` configuration saves `.eml` copies of messages
rejected by AI or attachment inspection. Copies are organized beneath the
configured directory as `YYYY/MM/DD`, making them easy to inspect or reuse for
testing. Cached IP rejections happen before the email is received and therefore
cannot be saved.

The archive may contain private correspondence and dangerous attachments, so
restrict access to it. Retention cleanup runs at startup and every 24 hours;
expired date directories are removed hierarchically. If the archive exceeds its
configured target size, daily cleanup removes the oldest retained messages until
it is below the target. Archive errors are logged but never alter the SMTP
filtering decision.

## Trusted mail and adaptive filtering

Authenticated outbound mail is not scanned by default. MilterGuard uses
accepted outbound mail to learn which external addresses each local user
corresponds with. These addresses are immediately whitelisted and can bypass
future scanning when the configured authentication requirements are met.
MilterGuard can also learn inbound senders that repeatedly receive a
high-confidence legitimate classification and pass the configured authentication
checks.

This reduces cost and avoids repeatedly classifying routine mail. Entire email
domains can also be whitelisted in the configured trusted-sender domains file.
The supplied file contains a curated low-risk sender list whose messages bypass
scanning only when trusted, aligned DKIM authentication passes. Merely forging
an address in one of these domains therefore does not bypass filtering.

For authenticated sender domains that still require scanning, the optional
`domain_registration` feature obtains the registrable domain's creation and
expiry dates through RDAP and supplies its age to the AI as supporting evidence.
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

Rejection history records the sender address, envelope recipient, rejection
time, subject, and reason for messages rejected after AI or attachment
inspection in enforce mode. It does not record cached-IP or unrelated Postfix
rejections. The `rejection_history` settings control its retention period and
maximum retained number of entries. The database may temporarily exceed this
target between maintenance runs; expired and excess oldest entries are then
removed automatically. An expiry of `0s` disables the history.

Learned correspondents, rejection history, IP reputation, and cached domain
registration data are stored in `/var/lib/milterguard` and survive service
restarts. Back up this directory if you want to preserve the learned state when
moving the service to another machine. Correspondent, IP reputation,
rejection-history, and domain-registration changes are committed to the SQLite
database immediately. `persistence.cleanup_interval` controls periodic removal
of expired and excess records and must be at least one minute; cleanup also runs
at startup. The same background maintenance task also checkpoints SQLite's
write-ahead log. Domain-registration expiry is still enforced during lookups,
before periodic cleanup physically removes the old row.

For a consistent backup, stop MilterGuard before copying its SQLite database,
or use a SQLite-aware backup tool while the service is running.

To add or remove correspondent whitelist entries directly from the command
line, stop MilterGuard while editing its database:

```sh
sudo systemctl stop milterguard
sudo milterguard --whitelist-add sender@example.com recipient@example.net
sudo milterguard --whitelist-del sender@example.com recipient@example.net
sudo milterguard --whitelist-del sender@example.com '*'
sudo systemctl start milterguard
```

The wildcard deletes that sender's entries for every local recipient.

## Email commands

MilterGuard provides a local command email address for managing allowlists
and reviewing rejected mail. Commands sent to this address are processed by
MilterGuard, and the results are emailed back to the user.

Enable and configure `email_commands` in
`/etc/milterguard/milterguard.yaml`. Set `recipient` to the local command
email address you want to use, for example:

```yaml
email_commands:
  enabled: true
  recipient: milterguard@example.com
```

Here, `example.com` must be replaced with a domain on which your server can
receive email.

Before enabling the mail command feature, add the following entry to
`/etc/aliases`:

```text
milterguard: /dev/null
```

Then run:

```sh
newaliases
```

For administrator-only operation, leave `allow_authenticated_users` set to
`false` and add the permitted SASL login names to the `administrators` list in
the `email_commands` section of `/etc/milterguard/milterguard.yaml`.
Administrators can manage or inspect any recipient and use `*` to select
everyone.

When `allow_authenticated_users` is `true`, any authenticated user can manage
and inspect their own allowlist and rejection history. MilterGuard can verify
address ownership using `/etc/aliases` if `verify_sender_via_aliases` is set to
`true`; otherwise Postfix must enforce it using `smtpd_sender_login_maps`.
Without either check, an authenticated user could manage another user's
allowlist and view their rejection history.

To execute a command, send an email to the configured command address
(`milterguard@example.com` in the example above) as its sole recipient, with
the required command as the first line of the email body.

Available commands:

```text
WHITELIST ADD sender@example.com
WHITELIST DELETE sender@example.com
WHITELIST LIST
REJECTIONS
HELP
```

Administrators may specify a recipient:

```text
WHITELIST ADD sender@example.com recipient@example.com
WHITELIST DELETE sender@example.com recipient@example.com
WHITELIST LIST recipient@example.com
REJECTIONS recipient@example.com
```

They may also use:

```text
WHITELIST DELETE sender@example.com *
WHITELIST LIST *
REJECTIONS *
```

Administrators can also manage the sending-IP block database:

```text
IP LIST
IP LIST LOOKUP
IP ADD 192.0.2.1
IP DELETE 192.0.2.1
```

`IP LIST` returns only IP addresses with a currently active short or
repeat-offender block. `IP LIST LOOKUP` also performs reverse-DNS lookups and
includes the hostname or `(not found)` after each address. Manually added
addresses use the configured repeat-offender block duration, or the short block
duration when repeat-offender blocking is disabled.

Command-result emails are submitted to the SMTP server configured by
`email_commands.smtp_host`, which defaults to `127.0.0.1:25`. Change it when
MilterGuard and the receiving MTA run on different machines. This connection
does not use TLS or SMTP authentication, so a remote SMTP host should be used
only over a trusted private network or a separately secured connection. Command
replies can contain allowlist and rejection-history data.

## Running AI locally

Running the AI locally is the recommended option. Email content remains on your
own infrastructure, classifications remain consistent, availability is under
your control, and there are no per-message API charges.

The recommended Qwen3.6-35B-A3B model provides strong results with relatively
modest hardware requirements. A system with an 8 GB GPU and 32 GB of system RAM
should work well with a suitable quantization and configuration.

The model is available from:

https://huggingface.co/unsloth/Qwen3.6-35B-A3B-GGUF

Choose the largest quantization that fits comfortably within the available GPU
and system memory. Quantizations below 4-bit may reduce classification quality
and are not recommended.

This practical guide explains how to run the model efficiently with limited GPU
memory:

https://piefed.crash.cx/c/localllama/p/123973/how-to-run-qwen-35b-a3b-on-4gb-to-8gb-of-vram-with-24-gb-system-ram

Serve the model through llama.cpp, available from:

https://github.com/ggml-org/llama.cpp

Set MilterGuard's AI timeout high enough for the slowest messages and image
analysis. The MTA's Milter timeout must be longer than MilterGuard's AI timeout.

Before using a local model on live mail, replay a representative collection of
legitimate, spam, and scam messages through a separate MilterGuard test instance.
Check both classification accuracy and response time before enabling enforcement.

## Routine operation

Keep the service, detection prompt, and model under review as the mail you receive
changes. Check the journal for rejected mail, endpoint errors, attachment-policy
decisions, and changes in classification quality. After changing the prompt,
model, confidence threshold, or filtering policy, repeat the saved-message tests
before restarting production.

When `filtering.add_email_headers` is enabled, every accepted message receives
`X-MilterGuard-Classification`, `X-MilterGuard-Score`,
`X-MilterGuard-Confidence`, and `X-MilterGuard-Action` headers where applicable.
`X-MilterGuard-Confidence: low` identifies unwanted classifications below
`reject_score`, or legitimate classifications below
`legitimate_low_confidence_score`. It can be used by a server-side or mail-client
rule to place borderline messages in a Junk folder. Bypassed messages and
analysis failures are marked as unavailable rather than being given an invented
score. MilterGuard removes incoming headers with these names before adding its
own values when Postfix offers Milter change-header support. The recommended
Postfix `header_checks` rule also removes them at the SMTP boundary. Downstream
filters should not trust these headers unless one of these protections is in
place.

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

Validate configuration changes before applying them:

```sh
milterguard --config /etc/milterguard/milterguard.yaml --check-config
```

## Replay saved email

Mailbox replay lets you test a MilterGuard configuration, AI model, and
detection prompt against a corpus of saved `.eml` files with known expected
outcomes. Use it before enabling enforcement or deploying changes to identify
false positives, missed spam, inconsistent classifications, and excessive
response times without processing the messages as live mail.

The release includes `tools/replay_mailbox.py`, which requires Python 3 and
submits every `.eml` file in a directory directly to a test MilterGuard
instance. The installer places it at
`/usr/local/share/milterguard/tools/replay_mailbox.py`.

Run a separate test instance in `enforce` mode on an unused port. Give its
configuration a separate `persistence.database_file` so testing cannot alter
production correspondent, rejection-history, or IP-reputation data. To ensure
every corpus message reaches the AI, set `ip_reputation.block_duration` to `0s`,
`ip_reputation.repeat_threshold` to `0`, and `correspondents.use_allowlist` to
`false` in the test configuration. The replay tool reports the actual Milter
response, so a test instance in `monitor` mode will report every message as
accepted even when MilterGuard recommends rejection.

By default, the replay tool reconstructs the SMTP peer IP, client hostname,
HELO identity, and receiving MTA hostname from the saved `Received` headers.
The MTA hostname allows locally generated DKIM, SPF, and DMARC results already
present in the message to be supplied to the AI as trusted evidence. It also
derives the envelope sender and recipient from `Return-Path`, `X-Original-To`,
`Delivered-To`, or the visible address headers. Each message uses a separate
Milter connection. Because saved headers do not preserve every original SMTP
detail, unavailable values are reported rather than guessed. Use
`--connection-info synthetic` for the previous deterministic loopback identity,
or the individual override options shown by `--help`.

Test representative directories and save the JSON Lines results:

```sh
python3 /usr/local/share/milterguard/tools/replay_mailbox.py \
  /path/to/legitimate --host 127.0.0.1 --port 8894 --expected accept \
  | tee legitimate-results.jsonl

python3 /usr/local/share/milterguard/tools/replay_mailbox.py \
  /path/to/spam --host 127.0.0.1 --port 8894 --expected reject \
  | tee spam-results.jsonl

python3 /usr/local/share/milterguard/tools/replay_mailbox.py \
  /path/to/scam --host 127.0.0.1 --port 8894 --expected reject \
  | tee scam-results.jsonl
```

Port 8894 is used above for the separate test instance of MilterGuard.

Each line records the file, result, expected result, whether they matched,
latency, SMTP rejection detail, reconstructed connection information, and the
envelope addresses used. The final line summarizes the run.
