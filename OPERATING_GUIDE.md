# MilterGuard Operating Guide

**Need help?** For technical questions about MilterGuard, give ChatGPT or Claude
the repository URL, https://github.com/PhilAnderson1/MilterGuard, and ask it to
consult the current source code and documentation. Check any suggested
configuration changes before applying them to a live mail server.

Using the supplied default configuration, MilterGuard will use AI to identify
unwanted spam and scam email, including threats concealed in images, and provide
basic virus protection by blocking executable attachments. By default, it will
not scan authenticated outbound email. It will initially monitor inbound email
without rejecting it, allowing you to confirm that its decisions are reliable
before enabling enforcement. Over time, it will learn and whitelist trusted email
senders, and identify and blacklist problematic sending IP addresses to reduce
false positives, false negatives, AI usage, and operating costs.

For initial installation and activation, follow the
[MilterGuard Quick Start](QUICKSTART.md).

## Contents

1. [Configure the AI service](#configure-the-ai-service)
2. [Install and configure OpenDKIM and OpenDMARC (optional)](#install-and-configure-opendkim-and-opendmarc-optional)
3. [Connect MilterGuard to Postfix](#connect-milterguard-to-postfix)
4. [Start in monitor mode](#start-in-monitor-mode)
5. [Enable enforcement](#enable-enforcement)
6. [Basic virus protection](#basic-virus-protection)
7. [Trusted mail and adaptive filtering](#trusted-mail-and-adaptive-filtering)
8. [Email commands](#email-commands)
9. [Running AI locally](#running-ai-locally)
10. [Routine operation](#routine-operation)
11. [Replay saved email](#replay-saved-email)

## Configure the AI service

MilterGuard's configuration file is `/etc/milterguard/milterguard.yaml`.
Edit it before starting the service, preserving its YAML indentation and using
spaces rather than tabs.

With the supplied OpenRouter configuration, replace the placeholder `ai.api_key`
with a valid key from https://openrouter.ai. The remaining settings can be used
unchanged for initial testing. If the example model is no longer available,
choose a current compatible model and retest before enabling rejection.

The email data used for classification is sent to the configured AI endpoint,
including selected headers, extracted message text, links, and qualifying inline
images. If email content must remain entirely private, use MilterGuard with a
locally hosted AI server; see the Running AI locally section. If you use
OpenRouter, its Privacy settings include a Zero Data Retention option that
restricts routing to providers with a zero-data-retention policy.

MilterGuard can use a locally operated llama.cpp server for AI functionality.
Set the endpoint and model in the configuration to match your local server. The
`endpoint_type` setting selects the endpoint-specific request used to disable
model thinking; choose `openrouter`, `llamacpp`, or `openai` to match the server. The
model must support image input if you want MilterGuard to examine email whose
message is contained in an image.

Image analysis detects scams that conceal their message inside an image to
evade text-based filtering. Set `vision_mode` to `off` to disable it,
`fallback` to examine qualifying inline images when insufficient text is
available, or `always` to examine them in every message. MilterGuard never
downloads remote images.

Before starting MilterGuard, review
`/etc/milterguard/detection-prompt.txt` and confirm that its unwanted-email
rules match what you want to reject. The supplied prompt and settings have been
tested with the configured model; another model may interpret the rules or
confidence scale differently. Keep prompt changes concise, and test any changed
prompt or model in monitor mode against representative legitimate and unwanted
email before enabling rejection.

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

These filters must run in this order:

```text
OpenDKIM → OpenDMARC → MilterGuard
```

The authentication service identifier written to `Authentication-Results`
must be included in MilterGuard's `correspondents.trusted_authserv_ids` setting.
The supplied `$mta_hostname` value normally handles results identified with the
Postfix hostname.

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
send representative test messages and observe real mail traffic.

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
time, and AI reasons for messages actually rejected in enforce mode. It does not
record attachment-policy, cached-IP, or unrelated Postfix rejections. The
`rejection_history` settings control its file, retention period, and maximum
number of entries; expired and excess oldest entries are removed automatically,
and an expiry of `0s` disables the history.

Learned correspondents, rejection history, and IP reputation are stored in
`/var/lib/milterguard` and survive service restarts. Back up this directory
if you want to preserve the learned state when moving the service to another
machine. Changes take effect in memory immediately and are written according to
`persistence.flush_interval`; a normal service shutdown also performs a final
write. Set the interval to `0s` to write every change immediately.

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
MilterGuard and the receiving MTA run on different machines.

## Running AI locally

A local AI model keeps sensitive email content within your own infrastructure
instead of sending it to a hosted AI provider, providing the strongest privacy
option. It also removes per-message API charges.

Choose a model that follows structured instructions reliably and returns
consistent classifications. Vision support is required to analyse scams
presented as images.

The default model, Qwen3.6-35B-A3B (freely available under open weights), has
relatively modest hardware requirements and can perform very well locally
when the mail server is fitted with a suitable GPU. It will even run entirely
on the CPU at reduced throughput if the server has sufficient free
RAM (approx. 32 GB) to load a reasonable quantization of the model.

The model may be downloaded from here:

https://huggingface.co/unsloth/Qwen3.6-35B-A3B-GGUF

Choose the biggest version that will fit your available memory, although
anything below 4-bit quantization may be less reliable and is not
recommended.

Serve the model using llama.cpp, available for download from here:

https://github.com/ggml-org/llama.cpp

Allow enough AI timeout for the slowest messages you expect to process. Large
messages and image analysis generally take longer than short text messages. Also
keep the MTA's Milter timeout longer than MilterGuard's AI timeout so that the
MTA does not abandon the request while analysis is still running.

Before adopting a local model, replay a representative collection of legitimate,
spam, and scam messages against a separate MilterGuard test instance. Compare
both accuracy and response time with the hosted model before switching production
traffic.

## Routine operation

Keep the service, detection prompt, and model under review as the mail you receive
changes. Check the journal for rejected mail, endpoint errors, attachment-policy
decisions, and changes in classification quality. After changing the prompt,
model, confidence threshold, or filtering policy, repeat the saved-message tests
before restarting production.

When `filtering.add_unwanted_headers` is enabled, an unwanted message accepted
because its score is below `reject_score` receives
`X-MilterGuard-Classification`, `X-MilterGuard-Score`, and
`X-MilterGuard-Action` headers. These can be used by a server-side or mail-client
rule to place borderline messages in a Junk folder. MilterGuard removes incoming
headers with these names before adding its own values.

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
configuration separate correspondent, rejection-history, and IP-reputation
state files so testing cannot alter production data. To ensure every corpus
message reaches the AI, set `ip_reputation.block_duration` to `0s`,
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
