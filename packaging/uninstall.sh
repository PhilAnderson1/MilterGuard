#!/bin/sh

set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "MilterGuard must be uninstalled as root." >&2
    exit 1
fi

echo "WARNING: This will permanently uninstall MilterGuard and delete:"
echo "  - /usr/local/sbin/milterguard"
echo "  - /usr/local/share/milterguard (testing utility)"
echo "  - /etc/milterguard (configuration and detection prompt)"
echo "  - /var/lib/milterguard (learned email correspondents and IP reputation)"
echo "  - /etc/systemd/system/milterguard.service"
echo ""
echo "The configuration and learned email/IP data cannot be recovered unless"
echo "you have made a backup."
echo ""
printf "Type 'uninstall' to continue: "
IFS= read -r confirmation

if [ "$confirmation" != "uninstall" ]; then
    echo "Uninstall cancelled."
    exit 0
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now milterguard.service >/dev/null 2>&1 || true
fi

rm -f /etc/systemd/system/milterguard.service
rm -f /usr/local/sbin/milterguard
rm -rf /usr/local/share/milterguard
rm -rf /etc/milterguard
rm -rf /var/lib/milterguard

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl reset-failed milterguard.service >/dev/null 2>&1 || true
fi

echo ""
printf "Remove the milterguard system user and group? [y/N] "
IFS= read -r remove_account

case "$remove_account" in
    y|Y|yes|YES|Yes)
        if id milterguard >/dev/null 2>&1; then
            if command -v userdel >/dev/null 2>&1; then
                if ! userdel milterguard; then
                    echo "WARNING: Could not remove the milterguard user." >&2
                fi
            elif command -v deluser >/dev/null 2>&1; then
                if ! deluser milterguard; then
                    echo "WARNING: Could not remove the milterguard user." >&2
                fi
            else
                echo "WARNING: userdel/deluser not found; the milterguard user remains." >&2
            fi
        fi

        if getent group milterguard >/dev/null 2>&1; then
            if command -v groupdel >/dev/null 2>&1; then
                if ! groupdel milterguard; then
                    echo "WARNING: Could not remove the milterguard group." >&2
                fi
            elif command -v delgroup >/dev/null 2>&1; then
                if ! delgroup milterguard; then
                    echo "WARNING: Could not remove the milterguard group." >&2
                fi
            else
                echo "WARNING: groupdel/delgroup not found; the milterguard group remains." >&2
            fi
        fi
        ;;
    *)
        echo "Preserving the milterguard system user and group."
        ;;
esac

echo "MilterGuard has been uninstalled."
