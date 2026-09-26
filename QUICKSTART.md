# MilterGuard Quick Start

This guide takes you from downloading MilterGuard to a working Postfix
integration in monitor mode. See the Operating Guide for detailed
configuration, security, testing, and maintenance information.

1. Download the appropriate installation file from the latest MilterGuard
   release:

   https://github.com/PhilAnderson1/MilterGuard/releases/latest

2. Install MilterGuard using the appropriate method below. Replace `VERSION`
   with the release number without its leading `v`.

   **Red Hat-based systems, including AlmaLinux:**

   ```sh
   sudo dnf install ./milterguard-VERSION-1.x86_64.rpm
   ```

   **Debian and Ubuntu:**

   ```sh
   sudo apt install ./milterguard_VERSION_amd64.deb
   ```

   **Other Linux systems:**

   ```sh
   tar -xzf milterguard-vVERSION-linux-amd64.tar.gz
   cd milterguard-vVERSION-linux-amd64
   sudo ./install.sh
   ```

3. Configure the AI service in `/etc/milterguard/milterguard.yaml`. A compatible
   locally hosted service is recommended, but the supplied configuration works
   with OpenRouter after adding an [OpenRouter API key](https://openrouter.ai)
   to `ai.api_key`. For another hosted service or a local AI server, configure
   the endpoint URL, endpoint type, model name, and API key. If the local server
   does not require authentication, use a non-empty placeholder key.

4. Validate the configuration:

   ```sh
   sudo milterguard \
     --config /etc/milterguard/milterguard.yaml \
     --check-config --check-port --check-endpoint
   ```

   This checks that the configuration file is valid and the configured Milter
   port is available, then sends a synthetic test email to the configured AI
   service and checks its response.

   If port `8895` is already in use, edit `milter.socket` in the configuration
   file to use an unused loopback port instead. Use that same replacement port
   in the Postfix `smtpd_milters` setting in step 6.

5. Enable and start MilterGuard:

   ```sh
   sudo systemctl enable --now milterguard
   ```

6. Add MilterGuard to the end of `smtpd_milters` in
   `/etc/postfix/main.cf`:

   ```text
   milter_content_timeout = 600s

   # MilterGuard only
   smtpd_milters = inet:127.0.0.1:8895
   ```

   If `smtpd_milters` already contains other filters, append MilterGuard to the
   existing comma-separated list and keep it last. For example:

   ```text
   smtpd_milters = unix:/run/existing-filter/filter.sock, inet:127.0.0.1:8895
   ```

   Do not add MilterGuard to `non_smtpd_milters`, because that setting also
   filters locally generated system mail.

7. Check and reload Postfix:

   ```sh
   sudo postfix check
   sudo postfix reload
   ```

MilterGuard should now be processing mail through Postfix. It initially runs in
`monitor` mode, so it analyses each message and logs its decision without
rejecting anything. Review its decisions by looking at the MilterGuard-added
headers in received emails or with:

```sh
sudo journalctl -u milterguard --since yesterday --no-pager -o cat
```

When its decisions have proved reliable, change `mode: monitor` to
`mode: enforce` in `/etc/milterguard/milterguard.yaml`, then activate
filtering with:

```sh
sudo systemctl restart milterguard
```

See the [Operating Guide](OPERATING_GUIDE.md) for detailed configuration,
testing, security, and maintenance information.

**Need help?** For technical questions about MilterGuard, give ChatGPT or Claude
the repository URL, https://github.com/PhilAnderson1/MilterGuard, and ask it to
consult the current source code and documentation. Check any suggested
configuration changes before applying them to a live mail server.
