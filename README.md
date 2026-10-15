# MilterGuard

<p align="center">
  <img src="assets/milterguard-logo.png"
       alt="MilterGuard — A shrewd eye for unwanted email"
       width="500">
</p>

[![CI](https://github.com/PhilAnderson1/MilterGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/PhilAnderson1/MilterGuard/actions/workflows/ci.yml)

MilterGuard is an AI-first spam and scam filter for Postfix that assesses email
by meaning, intent and context. It works with local or hosted AI models and is
designed to support other Milter-compatible mail servers.

[Quick start](QUICKSTART.md) · [Operating guide](OPERATING_GUIDE.md) · [Latest release](https://github.com/PhilAnderson1/MilterGuard/releases/latest)

## Why MilterGuard?

A convincing scam or unsolicited sales pitch can arrive from an authenticated
sender, contain no known malicious links, and look like ordinary
correspondence. Identifying it requires examining what the sender is asking,
what relationship they claim, and what responding could lead to.

MilterGuard prepares the evidence for that assessment. It brings together
sender identity, authentication, message content and link destinations, while
preserving clues about hidden or obscured HTML text. With a vision-capable
model, it can also examine messages embedded in images.

Its classification prompt examines identity, context, purpose and likely
continuation, weighing evidence of unwanted contact against legitimate
explanations—including genuine first contact. No locally trained classifier or
history of your email is required.

Built for everyday mail-server operation, MilterGuard learns trusted
correspondents and blocks repeat offenders to reduce unnecessary AI scans. It
installs as a single executable, lets you manage sender lists and review
rejected messages by email, and provides an accept mode for evaluating its
decisions before enabling rejection.

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

## Who is MilterGuard for?

MilterGuard is designed for administrators who run their own mail servers and
want AI-first spam and scam filtering integrated with their existing setup.
Postfix is the tested and documented platform.

It suits operators who want control over their classification model and
filtering policy, with the option to keep message analysis on their own
hardware. You can evaluate decisions in accept mode and test alternative models
or prompts against saved email before enabling rejection.

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
