# MilterGuard

[![CI](https://github.com/PhilAnderson1/MilterGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/PhilAnderson1/MilterGuard/actions/workflows/ci.yml)

MilterGuard is an AI-powered mail filter for identifying and rejecting unwanted
spam and scam email. It has been tested with Postfix and is designed to work
with any MTA that supports the Sendmail Milter protocol.

[Quick start](QUICKSTART.md) · [Operating guide](OPERATING_GUIDE.md) · [Latest release](https://github.com/PhilAnderson1/MilterGuard/releases/latest)

## Why MilterGuard?

- Uses multilingual semantic analysis to detect unwanted email by meaning and intent, not just keywords or signatures.
- Performs forensic AI analysis of message headers, body content, and hyperlink destinations.
- Reads text embedded in images to detect scams that evade conventional text-based filters.
- Blocks executable attachments, including files disguised or concealed inside compressed archives.
- Smart correspondent allowlisting learns trusted relationships and recurring legitimate senders, reducing false positives and unnecessary AI scans.
- Automatically builds persistent IP reputation to block repeat offenders without repeated AI analysis.
- Manage allowlists and review rejected mail remotely by email.
- Works with locally hosted AI models and popular AI API services.
- Provides a safe monitor mode that logs classifications and proposed actions without blocking email.
- Installs as a single, statically linked binary with no runtime dependencies.
- Includes native packages and install and uninstall scripts for painless installation and removal.

## Requirements

MilterGuard requires:

- A Linux mail server whose MTA supports the Sendmail Milter protocol. Postfix
  is tested and documented.
- Access to a suitable `v1/chat/completions` AI endpoint. Running the AI model
  locally is recommended, but MilterGuard also supports hosted services such as
  OpenRouter and OpenAI.

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
MilterGuard to the MTA, verify its decisions in monitor mode, and enable
filtering.

## Documentation

- [Quick Start](QUICKSTART.md) covers initial configuration and activation.
- [Operating Guide](OPERATING_GUIDE.md) covers AI providers, Postfix and
  authentication integration, filtering policy, adaptive reputation, email
  commands, testing, security, and maintenance.
- The annotated example configuration is available at
  [configs/milterguard.yaml](configs/milterguard.yaml).

## Build and install from source

Building requires Go 1.25 or later:

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
