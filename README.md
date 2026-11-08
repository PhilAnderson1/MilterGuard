# MilterGuard

<p align="center">
  <img src="assets/milterguard-logo.png"
       alt="MilterGuard — A shrewd eye for unwanted email"
       width="80%">
</p>

[![CI](https://github.com/PhilAnderson1/MilterGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/PhilAnderson1/MilterGuard/actions/workflows/ci.yml)

MilterGuard provides simple, effective spam and scam filtering for Postfix mail
servers. It’s designed to be easy to install, straightforward to configure and
immediately effective.

[Quick start](QUICKSTART.md) · [Operating guide](OPERATING_GUIDE.md) · [Latest release](https://github.com/PhilAnderson1/MilterGuard/releases/latest)

## How it works

MilterGuard is built from the ground up to use the reasoning and deductive
capabilities of modern AI to identify spam and scams through the meaning, intent
and context of each email. Unwanted mail can be rejected during SMTP delivery,
before it reaches the recipient’s inbox.

MilterGuard checks sender authentication and gives the AI both visible and
concealed message content, helping it identify deceptive emails and attempts
to evade filtering. With a vision-capable model, it can also read text embedded
in images.

## Who is MilterGuard for?

MilterGuard is intended for administrators of personal, family or small-business
self-hosted mail servers who want straightforward spam and scam protection
without managing a complex filtering system or training a spam classifier. It
has been tested with Postfix but is designed to work with any mail server that
supports the Sendmail Milter protocol.

## Features

- **Simple installation:** a single self-contained executable, with no additional
  libraries or separate database service to install.
- **AI model choice:** use a hosted AI service, or keep message analysis on your
  own hardware with a local model.
- **No spam/ham training required:** start filtering without assembling a
  training dataset.
- **Automatic sender trust and IP blocking:** learns trusted senders and blocks
  repeat offenders.
- **Email administration:** manage sender lists and review rejected messages by
  email.
- **Safe evaluation:** review decisions in accept mode before enabling rejection.
- **Image analysis:** examine content embedded in images with a vision-capable
  model.
- **Basic attachment protection:** block executable attachments, including those
  inside supported archives. This does not replace a full antivirus engine.

## Requirements

MilterGuard requires:

- A Linux mail server whose MTA supports the Sendmail Milter protocol. Postfix
  is tested and documented.
- Access to a compatible AI service or local model server.

The supplied packages and archive are for x86-64 Linux. The documented
installation uses systemd.

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

The supplied configuration uses OpenRouter; add your API key to get started.
Follow the [Quick Start](QUICKSTART.md) to connect MilterGuard to Postfix,
check its decisions in accept mode, and enable rejection.

## Performance (early results)

From 30 September to 4 November 2026, one production mail server accepted 397
inbound messages and recorded 792 MilterGuard rejections. There was one
false-positive rejection, two spam messages were accepted, and one scam message
was accepted.

Testing used Qwen3.6-35B-A3B through OpenRouter, with automatic learning of
trusted senders enabled.

These observations represent an approximate overall filtering accuracy of
99.7%. Estimated OpenRouter usage cost $1.85 over the five-week period, based
on an average of $0.37 per week.

These are early production observations, not a comparative benchmark.
Evaluation is ongoing.

## Documentation

- [Quick Start](QUICKSTART.md): installation and initial setup.
- [Operating Guide](OPERATING_GUIDE.md): configuration, administration and maintenance.
- [Example configuration](configs/milterguard.yaml): annotated settings.

## Build and install from source

Building requires Go 1.27.3 or later:

```sh
git clone https://github.com/PhilAnderson1/MilterGuard.git
cd MilterGuard
go test ./...
make
sudo ./packaging/install.sh
```

The installer preserves existing configuration files and enables the systemd
service without starting it. Continue with the
[Quick Start](QUICKSTART.md) to configure and activate MilterGuard.

## License

MilterGuard is available under the [MIT License](LICENSE). Licences and notices
for software incorporated into the compiled binary are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
