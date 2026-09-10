#!/bin/sh

set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "MilterGuard must be installed as root." >&2
    exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
binary="$script_dir/milterguard"
config_source="$script_dir/configs/milterguard.yaml"
prompt_source="$script_dir/configs/detection-prompt.txt"
trusted_domains_source="$script_dir/configs/trusted-sender-domains.txt"
replay_tool_source="$script_dir/tools/replay_mailbox.py"
service_source="$script_dir/packaging/systemd/milterguard.service"
quickstart_source="$script_dir/QUICKSTART.md"
operating_guide_source="$script_dir/OPERATING_GUIDE.md"
readme_source="$script_dir/README.md"
license_source="$script_dir/LICENSE"
third_party_notices_source="$script_dir/THIRD_PARTY_NOTICES.md"
third_party_licenses_source="$script_dir/THIRD_PARTY_LICENSES"

for required_file in "$binary" "$config_source" "$prompt_source" "$trusted_domains_source" "$replay_tool_source" "$quickstart_source" "$operating_guide_source" "$readme_source" "$license_source" "$third_party_notices_source"; do
    if [ ! -f "$required_file" ]; then
        echo "Required release file is missing: $required_file" >&2
        exit 1
    fi
done

if [ ! -d "$third_party_licenses_source" ]; then
    echo "Required release directory is missing: $third_party_licenses_source" >&2
    exit 1
fi

if ! getent group milterguard >/dev/null 2>&1; then
    if command -v groupadd >/dev/null 2>&1; then
        groupadd --system milterguard
    elif command -v addgroup >/dev/null 2>&1; then
        addgroup -S milterguard
    else
        echo "Cannot create the milterguard group: groupadd/addgroup not found." >&2
        exit 1
    fi
fi

if ! id milterguard >/dev/null 2>&1; then
    if command -v useradd >/dev/null 2>&1; then
        useradd --system --gid milterguard --home-dir /nonexistent --shell /usr/sbin/nologin milterguard
    elif command -v adduser >/dev/null 2>&1; then
        adduser -S -D -H -G milterguard -s /sbin/nologin milterguard
    else
        echo "Cannot create the milterguard user: useradd/adduser not found." >&2
        exit 1
    fi
fi

install -m 0755 "$binary" /usr/local/sbin/milterguard
install -d -o root -g milterguard -m 0750 /etc/milterguard
install -d -o milterguard -g milterguard -m 0750 /var/lib/milterguard
install -d -o milterguard -g milterguard -m 0750 /var/lib/milterguard/rejected-mail
install -d -o root -g root -m 0755 /usr/local/share/milterguard/tools
install -o root -g root -m 0755 "$replay_tool_source" /usr/local/share/milterguard/tools/replay_mailbox.py
install -o root -g root -m 0644 "$quickstart_source" /usr/local/share/milterguard/QUICKSTART.md
install -o root -g root -m 0644 "$operating_guide_source" /usr/local/share/milterguard/OPERATING_GUIDE.md
install -o root -g root -m 0644 "$readme_source" /usr/local/share/milterguard/README.md
install -o root -g root -m 0644 "$license_source" /usr/local/share/milterguard/LICENSE
install -o root -g root -m 0644 "$third_party_notices_source" /usr/local/share/milterguard/THIRD_PARTY_NOTICES.md
install -d -o root -g root -m 0755 /usr/local/share/milterguard/THIRD_PARTY_LICENSES
for third_party_license in "$third_party_licenses_source"/*.txt; do
    if [ ! -f "$third_party_license" ]; then
        echo "No third-party licence files found in: $third_party_licenses_source" >&2
        exit 1
    fi
    install -o root -g root -m 0644 "$third_party_license" /usr/local/share/milterguard/THIRD_PARTY_LICENSES/
done

install_config_if_missing() {
    source_file=$1
    destination_file=$2

    if [ -e "$destination_file" ]; then
        echo "Preserving existing $destination_file"
    else
        install -o root -g milterguard -m 0640 "$source_file" "$destination_file"
        echo "Installed $destination_file"
    fi
}

install_config_if_missing "$config_source" /etc/milterguard/milterguard.yaml
install_config_if_missing "$prompt_source" /etc/milterguard/detection-prompt.txt
install_config_if_missing "$trusted_domains_source" /etc/milterguard/trusted-sender-domains.txt

if [ -f "$service_source" ] && command -v systemctl >/dev/null 2>&1; then
    install -m 0644 "$service_source" /etc/systemd/system/milterguard.service
    systemctl daemon-reload
    echo "Installed the systemd service (not enabled or started)."
fi

echo "Installed MilterGuard to /usr/local/sbin/milterguard"
echo ""
echo "Edit /etc/milterguard/milterguard.yaml, then validate it with:"
echo "  /usr/local/sbin/milterguard --config /etc/milterguard/milterguard.yaml --check-config"
echo ""
if [ -f "$service_source" ] && command -v systemctl >/dev/null 2>&1; then
    echo "Enable and start MilterGuard with:"
    echo "  systemctl enable --now milterguard"
    echo ""
    echo "For an upgrade where MilterGuard is already running, restart it with:"
    echo "  systemctl restart milterguard"
fi
