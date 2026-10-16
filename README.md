# MilterGuard

<p align="center">
  <img src="assets/milterguard-logo.png"
       alt="MilterGuard — A shrewd eye for unwanted email"
       width="500">
</p>

[![CI](https://github.com/PhilAnderson1/MilterGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/PhilAnderson1/MilterGuard/actions/workflows/ci.yml)

MilterGuard provides simple, effective spam and scam filtering for Postfix mail
servers. It’s designed to be easy to install, straightforward to configure and
immediately effective.

[Quick start](QUICKSTART.md) · [Operating guide](OPERATING_GUIDE.md) · [Latest release](https://github.com/PhilAnderson1/MilterGuard/releases/latest)

## How it works

MilterGuard is built from the ground up to use the reasoning and deductive
capabilities of modern AI to identify spam and scams through the meaning, intent
and context of each email.

It gathers connection details, checks sender authentication through SPF, DKIM
and DMARC, and looks up domain age to give the AI context beyond the message
itself. It also converts HTML email into a text representation with visibility
tags, distinguishing visible content from hidden or obscured text so the AI can
assess both what the recipient sees and what may have been concealed in attempts
to evade spam filters. With a vision-capable model, it can also examine messages
embedded in images.

MilterGuard automatically builds an IP blocklist for repeat offenders and learns
trusted senders from legitimate correspondence. This reduces unnecessary AI
scans and helps refine filtering decisions over time.

## Who is MilterGuard for?

MilterGuard is intended for administrators of personal, family or small-business
self-hosted mail servers who want straightforward spam and scam protection
without managing a complex filtering system or training a spam classifier. It
has been tested with Postfix but is designed to work with any mail server that
supports the Sendmail Milter protocol.

## Features

- **Simple installation:** a single executable with no separate database service.
- **Model choice:** use a hosted AI service or run a model locally.
- **No spam/ham training required:** start filtering without assembling a
  training dataset.
- **Automatic adaptation:** learns trusted senders and blocks repeat offenders.
- **Email administration:** manage sender lists and review rejected messages by
  email.
- **Safe evaluation:** review decisions in accept mode before enabling rejection.
- **Image analysis:** examine content embedded in images with a vision-capable
  model.

## Early results

From 30 September to 15 October 2026, MilterGuard accepted 156 legitimate
inbound emails and recorded 284 spam or fraud rejections on one production mail
server. One rejection was borderline: marketing outreach following a website
signup. No other misclassifications were observed.

Testing used the Qwen3.6-35B-A3B model and an empty trusted-domain allowlist,
with adaptive correspondent learning enabled. Repeated legitimate newsletters
could therefore bypass subsequent AI scans. Rejection counts represent delivery
attempts and may include retries.

These are early production observations, not a comparative benchmark.
Evaluation is ongoing.

## Requirements

MilterGuard requires:

- A Linux mail server whose MTA supports the Sendmail Milter protocol. Postfix
  is tested and documented.
- Access to a suitable `v1/chat/completions` AI endpoint, using a local model
  or a hosted service such as OpenRouter or OpenAI.

## Install

Download the appropriate installation file from the
[latest release](https://github.com/PhilAnderson1/MilterGuard/releases/latest).
Replace `VERSION` below with the release number without its leading `v`.

On Red Hat-based systems, including AlmaLinux:

```sh
sudo dnf install ./milterguard-VERSION-1.x86_64.rpm
```

On Debian and Ubuntu:

```sh
sudo apt install ./milterguard_VERSION_amd64.deb
```

On other Linux systems, use the portable archive:

```sh
tar -xzf milterguard-vVERSION-linux-amd64.tar.gz
cd milterguard-vVERSION-linux-amd64
sudo ./install.sh
```

Continue with the [Quick Start](QUICKSTART.md) to add an AI API key, connect
MilterGuard to the MTA, verify its decisions in accept mode, and enable
filtering.

## Documentation

- [Quick Start](QUICKSTART.md) covers initial configuration and activation.
- [Operating Guide](OPERATING_GUIDE.md) covers AI providers, Postfix and
  authentication integration, filtering policy, adaptive reputation, email
  commands, testing, security, and maintenance.
- The annotated example configuration is available at
  [configs/milterguard.yaml](configs/milterguard.yaml).

## Build and install from source

Building requires Go 1.26 or later:

```sh
git clone https://github.com/PhilAnderson1/MilterGuard.git
cd MilterGuard
go test ./...
make
sudo ./packaging/install.sh
```

The installer recognizes the source-tree layout, installs the compiled binary
and supporting files, and preserves existing configuration files. Continue
with the [Quick Start](QUICKSTART.md) to configure and activate MilterGuard.

## License

MilterGuard is available under the [MIT License](LICENSE). Licences and notices
for software incorporated into the compiled binary are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
