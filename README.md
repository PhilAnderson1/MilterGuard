# MilterGuard

[![CI](https://github.com/PhilAnderson1/MilterGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/PhilAnderson1/MilterGuard/actions/workflows/ci.yml)

MilterGuard is an AI-powered mail filter for identifying and rejecting unwanted spam and scam email. It has been tested with Postfix but is designed to work with any MTA that supports the Sendmail Milter protocol.

[Quick start](QUICKSTART.md) · [Operating guide](OPERATING_GUIDE.md)

## Why MilterGuard?

- Uses semantic analysis to detect unwanted email by meaning, not just keywords or signatures.
- Performs forensic AI analysis of message headers, body content, and hyperlink destinations.
- Reads text embedded in images to detect scams that evade conventional text-based filters.
- Blocks executable attachments, including files disguised or concealed inside compressed archives.
- Smart correspondent allowlisting learns trusted relationships and recurring legitimate senders, reducing false positives and unnecessary AI scans.
- Automatically builds persistent IP reputation to block repeat offenders without repeated AI analysis.
- Manage allowlists and review rejected mail securely by email.
- Can scan inbound and outbound email, helping protect your server's sending reputation.
- Installs as a single, statically linked binary with no runtime dependencies.
- Provides a safe monitor mode that logs classifications and proposed actions without blocking email.
- Cost-effective to operate at approximately $0.35 per 1,000 scanned emails with the suggested LLM, depending on message length and provider pricing.
- Avoids provider lock-in by supporting compatible hosted AI services and locally hosted AI models.
- Includes install and uninstall scripts for painless installation and removal.

MilterGuard works with OpenRouter, OpenAI and llama.cpp-style `v1/chat/completions` AI endpoints.

## Install

Download the archive for your system from the [latest MilterGuard release](https://github.com/PhilAnderson1/MilterGuard/releases/latest):

| Linux architecture | Release archive suffix |
| --- | --- |
| x86-64 / AMD64 | `linux-amd64.tar.gz` |
| ARM64 / AArch64 | `linux-arm64.tar.gz` |
| 32-bit x86 | `linux-386.tar.gz` |
| ARMv7 | `linux-armv7.tar.gz` |

Extract the downloaded archive and run its installer. For example, for an AMD64 system:

```sh
tar -xzf milterguard-v0.2.5-linux-amd64.tar.gz
cd milterguard-v0.2.5-linux-amd64
sudo ./install.sh
```

The release binaries are statically linked. The installer places the executable in `/usr/local/sbin`, installs the configuration files in `/etc/milterguard`, installs documentation and the optional mailbox replay tool in `/usr/local/share/milterguard`, and installs the systemd unit when systemd is available. Existing configuration files are preserved.

### Configuration

Edit `/etc/milterguard/milterguard.yaml` before starting the service. To use a hosted AI model, get an API key from [OpenRouter](https://openrouter.ai/), then add the key to the `ai` section - if the example model is no longer available, select a current compatible model and adjust the prompt or settings if necessary. Alternatively, change the endpoint and model to use a locally operated llama.cpp `v1/chat/completions` server. An API key can be stored in `ai.api_key` or supplied through the environment variable named by `ai.api_key_env`.

Leave MilterGuard in `monitor` mode initially so that it records classifications and proposed actions without rejecting messages.

For Postfix, add the following to `main.cf` (ensure Postfix's milter content timeout remains above the AI timeout):

```text
smtpd_milters = inet:127.0.0.1:8895
non_smtpd_milters = inet:127.0.0.1:8895
milter_default_action = accept
milter_protocol = 6
```

MilterGuard uses DKIM, SPF and DMARC results supplied by earlier mail filters as evidence. List authentication Milters before MilterGuard in your Postfix configuration to improve classification accuracy.

Keep TCP listeners bound to a loopback address unless Postfix runs on another
machine. In that case, add only the Postfix server's network address to
`milter.allowed_peer_ips` and restrict access with a firewall as well.

Validate the configuration before enabling the service:

```sh
sudo /usr/local/sbin/milterguard --config /etc/milterguard/milterguard.yaml --check-config
sudo systemctl enable --now milterguard
```

Reload Postfix after changing `main.cf`:

```sh
sudo postfix reload
```

Send representative legitimate and unwanted test messages, then monitor MilterGuard's classifications, scores, reasons, proposed actions, and actual actions:

```sh
sudo journalctl -u milterguard --since yesterday --no-pager -o cat
```

Once monitor-mode results are satisfactory, change `mode: monitor` to `mode: enforce` in `/etc/milterguard/milterguard.yaml` and restart MilterGuard:

```sh
sudo systemctl restart milterguard
```

## Build from source

If a prebuilt binary is not suitable for your system, build MilterGuard with Go 1.22 or later:

```sh
git clone https://github.com/PhilAnderson1/MilterGuard.git
cd MilterGuard
go test ./...
CGO_ENABLED=0 go build -trimpath -o milterguard ./cmd/milterguard
```

Install the resulting binary, configuration, prompt, and systemd unit:

```sh
sudo install -m 0755 milterguard /usr/local/sbin/milterguard
getent group milterguard >/dev/null || sudo groupadd --system milterguard
id milterguard >/dev/null 2>&1 || sudo useradd --system --gid milterguard --home-dir /nonexistent --shell /usr/sbin/nologin milterguard
sudo install -d -o root -g milterguard -m 0750 /etc/milterguard
sudo install -d -o milterguard -g milterguard -m 0750 /var/lib/milterguard
sudo install -o root -g milterguard -m 0640 configs/milterguard.yaml /etc/milterguard/
sudo install -o root -g milterguard -m 0640 configs/detection-prompt.txt /etc/milterguard/
sudo install -m 0644 packaging/systemd/milterguard.service /etc/systemd/system/
sudo systemctl daemon-reload
```

Then edit and validate the configuration as described in the installation section above.

## License

MilterGuard is available under the [MIT License](LICENSE).
Licences and notices for software incorporated into the compiled binary are
listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
