# MilterGuard Quick Start

**Need help?** For technical questions about MilterGuard, give ChatGPT or Claude
the repository URL—https://github.com/PhilAnderson1/MilterGuard—and ask it to
consult the current source code and documentation. Check any suggested
configuration changes before applying them to a live mail server.

1. Install MilterGuard as root from the extracted release directory:

   ```sh
   sudo ./install.sh
   ```

2. If you do not operate a compatible local AI server and do not already have a
   compatible hosted API key, create an OpenRouter account and key at
   https://openrouter.ai.

3. Edit `/etc/milterguard/milterguard.yaml` and put the API key in the
   `ai.api_key` setting.

4. Validate the configuration:

   ```sh
   sudo milterguard \
     --config /etc/milterguard/milterguard.yaml --check-config
   ```

5. Enable and start MilterGuard:

   ```sh
   sudo systemctl enable --now milterguard
   ```

6. Add MilterGuard to the end of the Milter lists in
   `/etc/postfix/main.cf`. For example, when an existing DKIM Milter uses port
   8891:

   ```text
   smtpd_milters = inet:localhost:8891, inet:127.0.0.1:8895
   non_smtpd_milters = inet:localhost:8891, inet:127.0.0.1:8895
   ```

7. Check and reload Postfix:

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
