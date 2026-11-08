# MilterGuard Quick Start

Install MilterGuard, connect it to Postfix, and check its decisions before
enabling spam and scam rejection.

1. Download the appropriate installation file from the
   [latest release](https://github.com/PhilAnderson1/MilterGuard/releases/latest).

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

3. Configure the AI service in `/etc/milterguard/milterguard.yaml` by adding
   your [OpenRouter API key](https://openrouter.ai) to `ai.api_key`. To use a
   local LLM or another provider, see
   [Endpoint and model settings](OPERATING_GUIDE.md#endpoint-and-model-settings).

4. Validate the configuration:

   ```sh
   sudo milterguard \
     --config /etc/milterguard/milterguard.yaml \
     --check-config --check-port --check-endpoint
   ```

   This checks the configuration, confirms the listening port is available,
   and tests the AI service.

   If port `8895` is already in use, edit `milter.socket` in the configuration
   file to use an unused loopback port instead. Use that same replacement port
   in the Postfix `smtpd_milters` setting in step 6.

5. Installation enables the service without starting it. Start it now:

   ```sh
   sudo systemctl start milterguard
   ```

6. Add MilterGuard to the end of `smtpd_milters` in
   `/etc/postfix/main.cf`:

   ```text
   milter_default_action = accept
   milter_protocol = 6
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

   Check the
   [required Postfix connection data](OPERATING_GUIDE.md#required-postfix-connection-data)
   so it can verify mail and recognize authenticated outbound submissions.

7. Check and reload Postfix:

   ```sh
   sudo postfix check
   sudo postfix reload
   ```

   MilterGuard should now be processing mail through Postfix. It initially runs in
   `accept` mode, so it analyses inbound mail and logs its decisions without
   rejecting anything. Review its decisions by looking at the MilterGuard-added
   headers in received emails or with:

   ```sh
   sudo journalctl -u milterguard --since yesterday --no-pager -o cat
   ```

8. Enable rejection:

   When its decisions have proved reliable, change `mode: accept` to
   `mode: enforce` in `/etc/milterguard/milterguard.yaml`, then restart
   MilterGuard to enable rejection:

   ```sh
   sudo systemctl restart milterguard
   ```

For further configuration and troubleshooting, see the
[Operating Guide](OPERATING_GUIDE.md).
