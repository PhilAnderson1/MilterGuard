#!/bin/sh

set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "MilterGuard must be uninstalled as root." >&2
    exit 1
fi

if command -v dpkg-query >/dev/null 2>&1 &&
    dpkg-query -W -f='${Status}\n' milterguard 2>/dev/null | grep -qx 'install ok installed'; then
    echo "MilterGuard is managed by Debian packaging; use 'apt remove milterguard' or 'apt purge milterguard'." >&2
    exit 1
fi
if command -v rpm >/dev/null 2>&1 && rpm -q milterguard >/dev/null 2>&1; then
    echo "MilterGuard is managed by RPM packaging; use 'dnf remove milterguard'." >&2
    exit 1
fi

echo "WARNING: This will permanently uninstall MilterGuard and delete:"
echo "  - /usr/local/sbin/milterguard"
echo "  - /usr/local/share/milterguard (documentation, reference configuration,"
echo "    licences, and testing utility)"
echo "  - /etc/milterguard (configuration, AI catalogues, detection prompt, and trusted domains)"
echo "  - /var/lib/milterguard (database, learned state, rejection history,"
echo "    archived messages, activity data, and domain-registration cache)"
echo "  - /run/milterguard (runtime files and sockets)"
echo "  - /etc/systemd/system/milterguard.service"
echo ""
echo "The configuration and persistent data cannot be recovered unless you have"
echo "made a backup."
echo ""
printf "Type 'uninstall' to continue: "
confirmation=
if ! IFS= read -r confirmation; then
    echo ""
    echo "Uninstall cancelled."
    exit 0
fi

if [ "$confirmation" != "uninstall" ]; then
    echo "Uninstall cancelled."
    exit 0
fi

have_systemctl=false
if command -v systemctl >/dev/null 2>&1; then
    have_systemctl=true
    if systemctl is-active --quiet milterguard.service; then
        if ! systemctl stop milterguard.service; then
            echo "Cannot stop milterguard.service; no files were deleted." >&2
            exit 1
        fi
        if systemctl is-active --quiet milterguard.service; then
            echo "milterguard.service remains active; no files were deleted." >&2
            exit 1
        fi
    fi
    if ! systemctl disable milterguard.service >/dev/null 2>&1; then
        echo "WARNING: systemctl could not disable milterguard.service; removing its known enablement link directly." >&2
    fi
fi

rm -f /etc/systemd/system/multi-user.target.wants/milterguard.service
rm -f /etc/systemd/system/milterguard.service
rm -f /usr/local/sbin/milterguard
rm -rf /usr/local/share/milterguard
rm -rf /etc/milterguard
rm -rf /var/lib/milterguard
rm -rf /run/milterguard

if [ "$have_systemctl" = true ]; then
    if ! systemctl daemon-reload; then
        echo "WARNING: systemctl daemon-reload failed; reload systemd after correcting the service-manager problem." >&2
    fi
    systemctl reset-failed milterguard.service >/dev/null 2>&1 || true
fi

echo ""
printf "Remove the milterguard system user and group? [y/N] "
remove_account=
if ! IFS= read -r remove_account; then
    echo ""
    echo "No response received; preserving the milterguard system user and group."
fi

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
