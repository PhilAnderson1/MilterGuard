# MilterGuard Quick Start

This guide takes you from downloading MilterGuard to a working Postfix
integration in monitor mode. See the Operating Guide for detailed
configuration, security, testing, and maintenance information.

1. Download the archive for your Linux architecture from the latest MilterGuard
   release, then extract it and enter the resulting directory, replacing
   `VERSION` and the architecture as appropriate:

   https://github.com/PhilAnderson1/MilterGuard/releases/latest

   ```sh
   tar -xzf milterguard-VERSION-linux-amd64.tar.gz
   cd milterguard-VERSION-linux-amd64
   ```

2. Install MilterGuard as root:

   ```sh
   sudo ./install.sh
   ```

3. Choose the AI service MilterGuard will use. A compatible locally hosted AI
   server is recommended; see the Operating Guide for more information. If you
   do not operate one, create an OpenRouter account and API key at
   https://openrouter.ai. Using the recommended model typically costs around
   US$0.35 per 1,000 scanned emails, although the actual cost varies with message
   length and provider pricing.

4. Edit `/etc/milterguard/milterguard.yaml`. For OpenRouter, the supplied
   settings should work after adding your API key to `ai.api_key`. For another
   hosted service or a local AI server, configure the endpoint URL, endpoint
   type, model name, and API key. If the local server does not require
   authentication, use a non-empty placeholder key.

5. Validate the configuration:

   ```sh
   sudo /usr/local/sbin/milterguard \
     --config /etc/milterguard/milterguard.yaml --check-config
   ```

6. Enable and start MilterGuard:

   ```sh
   sudo systemctl enable --now milterguard
   ```

7. Add MilterGuard to the end of the Milter lists in
   `/etc/postfix/main.cf`. Use the appropriate example for your server:

   ```text
   # MilterGuard only
   smtpd_milters = inet:127.0.0.1:8895
   non_smtpd_milters = inet:127.0.0.1:8895

   # OpenDKIM, OpenDMARC and MilterGuard
   smtpd_milters = inet:127.0.0.1:8891, inet:127.0.0.1:8892, inet:127.0.0.1:8895
   non_smtpd_milters = inet:127.0.0.1:8891, inet:127.0.0.1:8892, inet:127.0.0.1:8895
   ```

   If you use OpenDKIM without OpenDMARC, omit the port 8892 entry. Use the
   actual ports or sockets configured on your server, and keep MilterGuard
   last.

8. Configure Postfix to remove externally supplied authentication and
   MilterGuard result headers before the Milters run, preventing remote senders
   from forging trusted evidence. Add this rule to `/etc/postfix/header_checks`:

   ```text
   /^Authentication-Results:/ IGNORE
   /^X-MilterGuard-(Classification|Score|Confidence|Action):/ IGNORE
   ```

   Then enable that table in `/etc/postfix/main.cf`, merging it with any
   existing `header_checks` configuration:

   ```text
   header_checks = regexp:/etc/postfix/header_checks
   ```

9. Check and reload Postfix:

   ```sh
   sudo postfix check
   sudo postfix reload
   ```

MilterGuard initially runs in `monitor` mode: it analyses mail and logs its
decisions without rejecting anything. Review its decisions with:

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
