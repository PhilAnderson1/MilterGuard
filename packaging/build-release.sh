#!/bin/sh
# Build the Linux x86-64 release archive and native Ubuntu/AlmaLinux packages.
set -eu

usage() {
    echo "Usage: $0 vMAJOR.MINOR.PATCH [--format all|tar|deb|rpm] [--output DIRECTORY] [--allow-dirty]" >&2
    exit 2
}

[ "$#" -ge 1 ] || usage
version=$1
shift
printf '%s\n' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || usage
package_version=${version#v}
format=all
allow_dirty=false
output_dir=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --format)
            [ "$#" -ge 2 ] || usage
            format=$2
            shift 2
            ;;
        --allow-dirty)
            allow_dirty=true
            shift
            ;;
        --output)
            [ "$#" -ge 2 ] || usage
            output_dir=$2
            shift 2
            ;;
        *) usage ;;
    esac
done
case "$format" in all|tar|deb|rpm) ;; *) usage ;; esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
source_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$source_dir"
if [ -z "$output_dir" ]; then
    output_dir="$source_dir/dist"
fi

need() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "Missing required build tool: $1" >&2
        exit 1
    }
}
for tool in git go install cp mktemp tar sha256sum; do need "$tool"; done
case "$format" in all|deb) need dpkg-deb ;; esac
case "$format" in all|rpm) need rpmbuild ;; esac

if [ "$allow_dirty" = false ] && [ -n "$(git status --porcelain)" ]; then
    echo "Working tree is not clean; commit the release or pass --allow-dirty for a test build." >&2
    exit 1
fi
if git rev-parse -q --verify "refs/tags/$version" >/dev/null 2>&1; then
    tag_commit=$(git rev-list -n 1 "$version")
    head_commit=$(git rev-parse HEAD)
    if [ "$tag_commit" != "$head_commit" ]; then
        echo "Tag $version does not point at HEAD; refusing to mislabel the build." >&2
        exit 1
    fi
fi

work_dir=$(mktemp -d "$source_dir/.release-build.XXXXXXXX")
case "$work_dir" in "$source_dir"/.release-build.*) ;; *) exit 1 ;; esac
trap 'rm -rf -- "$work_dir"' EXIT
trap 'exit 1' HUP INT TERM
artifacts="$work_dir/artifacts"
mkdir -p "$artifacts" "$work_dir/go-tmp"
# Go executes test binaries from GOTMPDIR. /tmp may be mounted noexec.
GOTMPDIR="$work_dir/go-tmp"
export GOTMPDIR

echo "Testing $(git rev-parse --short HEAD)..."
go test ./cmd/... ./internal/...
echo "Building MilterGuard $version for linux/amd64..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath \
    -ldflags "-s -w -X main.version=$version" \
    -o "$work_dir/milterguard" ./cmd/milterguard
if [ "$("$work_dir/milterguard" --version)" != "MilterGuard $version" ]; then
    echo "Built binary does not report $version" >&2
    exit 1
fi

stage_archive() {
    archive_root="milterguard-$version-linux-amd64"
    archive_dir="$work_dir/$archive_root"
    mkdir -p "$archive_dir/packaging/systemd"
    install -m 0755 "$work_dir/milterguard" "$archive_dir/milterguard"
    install -m 0755 packaging/install.sh packaging/uninstall.sh "$archive_dir/packaging/"
    install -m 0644 packaging/systemd/milterguard.service "$archive_dir/packaging/systemd/"
    cp -R configs THIRD_PARTY_LICENSES "$archive_dir/"
    install -d "$archive_dir/tools"
    install -m 0755 tools/replay_mailbox.py "$archive_dir/tools/replay_mailbox.py"
    install -m 0644 README.md QUICKSTART.md OPERATING_GUIDE.md LICENSE THIRD_PARTY_NOTICES.md "$archive_dir/"
    tar -C "$work_dir" -czf "$artifacts/$archive_root.tar.gz" "$archive_root"
}

# Native packages do not use the interactive tarball installer/uninstaller.
# Debian removal preserves configuration and state, while Debian purge and
# final RPM removal delete all MilterGuard configuration, state and accounts.
stage_native_payload() {
    payload="$work_dir/native"
    install -d "$payload/usr/sbin" "$payload/usr/lib/systemd/system" \
        "$payload/etc/milterguard" "$payload/usr/share/milterguard/tools" \
        "$payload/usr/share/doc/milterguard/THIRD_PARTY_LICENSES"
    install -m 0755 "$work_dir/milterguard" "$payload/usr/sbin/milterguard"
    sed 's@ExecStart=/usr/local/sbin/milterguard@ExecStart=/usr/sbin/milterguard@' \
        packaging/systemd/milterguard.service > "$payload/usr/lib/systemd/system/milterguard.service"
    install -m 0640 configs/milterguard.yaml "$payload/etc/milterguard/milterguard.yaml"
    install -m 0640 configs/detection-prompt.txt "$payload/etc/milterguard/detection-prompt.txt"
    install -m 0640 configs/trusted-sender-domains.txt "$payload/etc/milterguard/trusted-sender-domains.txt"
    install -m 0755 tools/replay_mailbox.py "$payload/usr/share/milterguard/tools/replay_mailbox.py"
    install -m 0644 README.md QUICKSTART.md OPERATING_GUIDE.md LICENSE THIRD_PARTY_NOTICES.md \
        "$payload/usr/share/doc/milterguard/"
    install -m 0644 THIRD_PARTY_LICENSES/* "$payload/usr/share/doc/milterguard/THIRD_PARTY_LICENSES/"
    cat > "$payload/usr/share/doc/milterguard/PACKAGED_INSTALL.md" <<'EOF'
# Package installation

On Ubuntu, install the downloaded `.deb` with `sudo apt install ./milterguard_*.deb`.
On AlmaLinux, install the `.rpm` with `sudo dnf install ./milterguard-*.rpm`.

The package installs `/usr/sbin/milterguard`, creates the `milterguard` account,
and installs a systemd unit. It does not enable or start the service. Edit
`/etc/milterguard/milterguard.yaml` and follow the Quick Start from its AI
configuration step onward, substituting `/usr/sbin/milterguard` for the
tarball's `/usr/local/sbin/milterguard`. Check the endpoint before starting:

    sudo /usr/sbin/milterguard --config /etc/milterguard/milterguard.yaml --check-config --check-port --check-endpoint
    sudo systemctl enable --now milterguard

Configuration is preserved on upgrade. On Debian and Ubuntu, `apt remove`
preserves configuration, the SQLite database, archived mail and the service
account; `apt purge` permanently deletes them. RPM has no separate purge
operation, so final removal with `dnf remove` permanently deletes configuration,
state and the service account. Back up `/etc/milterguard` and
`/var/lib/milterguard` before a destructive removal if their contents are needed.

Avoid installing a package over the tarball installation without first
migrating the latter: its `/etc/systemd/system/milterguard.service` overrides
the package's unit, and its `/usr/local/sbin/milterguard` remains separately
installed.
EOF
}

build_deb() {
    deb_root="$work_dir/deb"
    cp -R "$payload" "$deb_root"
    install -d "$deb_root/DEBIAN"
    cat > "$deb_root/DEBIAN/control" <<EOF
Package: milterguard
Version: $package_version
Section: mail
Priority: optional
Architecture: amd64
Maintainer: MilterGuard contributors <PhilAnderson1@users.noreply.github.com>
Depends: passwd, systemd
Description: AI-assisted mail filter for spam and scam email
 MilterGuard integrates with Postfix to classify unwanted mail.
EOF
    cat > "$deb_root/DEBIAN/conffiles" <<'EOF'
/etc/milterguard/milterguard.yaml
/etc/milterguard/detection-prompt.txt
/etc/milterguard/trusted-sender-domains.txt
EOF
    cat > "$deb_root/DEBIAN/preinst" <<'EOF'
#!/bin/sh
set -e
if ! getent group milterguard >/dev/null; then
    groupadd --system milterguard
fi
if ! id milterguard >/dev/null 2>&1; then
    useradd --system --gid milterguard --home-dir /nonexistent --shell /usr/sbin/nologin milterguard
fi
exit 0
EOF
    cat > "$deb_root/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = configure ]; then
    install -d -o root -g milterguard -m 0750 /etc/milterguard
    for name in milterguard.yaml detection-prompt.txt trusted-sender-domains.txt; do
        path="/etc/milterguard/$name"
        if [ -f "$path" ] && [ ! -L "$path" ]; then
            chown root:milterguard "$path"
            chmod 0640 "$path"
        fi
    done
    install -d -o milterguard -g milterguard -m 0750 /var/lib/milterguard /var/lib/milterguard/rejected-mail
    if command -v systemctl >/dev/null 2>&1; then
        if [ -e /etc/systemd/system/milterguard.service ]; then
            echo "WARNING: /etc/systemd/system/milterguard.service overrides the packaged unit; check for an earlier tarball installation." >&2
        fi
        systemctl daemon-reload || true
        if [ -n "${2:-}" ] && systemctl is-active --quiet milterguard.service; then
            systemctl try-restart milterguard.service || true
        fi
    fi
fi
exit 0
EOF
    cat > "$deb_root/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = remove ] && command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now milterguard.service || true
fi
exit 0
EOF
    cat > "$deb_root/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi
if [ "$1" = purge ]; then
    rm -rf -- /etc/milterguard /var/lib/milterguard
    if id milterguard >/dev/null 2>&1; then
        userdel milterguard || echo "WARNING: Could not remove the milterguard user." >&2
    fi
    if getent group milterguard >/dev/null; then
        groupdel milterguard || echo "WARNING: Could not remove the milterguard group." >&2
    fi
fi
exit 0
EOF
    chmod 0755 "$deb_root/DEBIAN/preinst" "$deb_root/DEBIAN/postinst" \
        "$deb_root/DEBIAN/prerm" "$deb_root/DEBIAN/postrm"
    dpkg-deb --root-owner-group --build "$deb_root" \
        "$artifacts/milterguard_${package_version}_amd64.deb"
}

build_rpm() {
    rpm_top="$work_dir/rpm"
    mkdir -p "$rpm_top/BUILD" "$rpm_top/BUILDROOT" "$rpm_top/RPMS" \
        "$rpm_top/SOURCES" "$rpm_top/SPECS" "$rpm_top/SRPMS" "$rpm_top/tmp"
    cat > "$rpm_top/SPECS/milterguard.spec" <<EOF
Name: milterguard
Version: $package_version
Release: 1
Summary: AI-assisted mail filter for spam and scam email
License: MIT
URL: https://github.com/PhilAnderson1/MilterGuard
BuildArch: x86_64
AutoReqProv: no
Requires(pre): shadow-utils
Requires(post): systemd

%description
MilterGuard integrates with Postfix to classify unwanted mail.

%prep

%build

%install
mkdir -p %{buildroot}
cp -a %{_staging}/. %{buildroot}/

%pre
if ! getent group milterguard >/dev/null; then
    groupadd -r milterguard
fi
if ! id milterguard >/dev/null 2>&1; then
    useradd -r -g milterguard -d /nonexistent -s /usr/sbin/nologin milterguard
fi

%post
install -d -o milterguard -g milterguard -m 0750 /var/lib/milterguard /var/lib/milterguard/rejected-mail
if command -v systemctl >/dev/null 2>&1; then
    if [ -e /etc/systemd/system/milterguard.service ]; then
        echo "WARNING: /etc/systemd/system/milterguard.service overrides the packaged unit; check for an earlier tarball installation." >&2
    fi
    systemctl daemon-reload || true
fi

%posttrans
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet milterguard.service; then
    systemctl try-restart milterguard.service || true
fi

%preun
if [ "\$1" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now milterguard.service || true
fi

%postun
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi
if [ "\$1" -eq 0 ]; then
    rm -rf -- /etc/milterguard /var/lib/milterguard
    if id milterguard >/dev/null 2>&1; then
        userdel milterguard || echo "WARNING: Could not remove the milterguard user." >&2
    fi
    if getent group milterguard >/dev/null; then
        groupdel milterguard || echo "WARNING: Could not remove the milterguard group." >&2
    fi
fi

%files
%defattr(-,root,root,-)
%dir %attr(0750,root,milterguard) /etc/milterguard
%config(noreplace) %attr(0640,root,milterguard) /etc/milterguard/milterguard.yaml
%config(noreplace) %attr(0640,root,milterguard) /etc/milterguard/detection-prompt.txt
%config(noreplace) %attr(0640,root,milterguard) /etc/milterguard/trusted-sender-domains.txt
/usr/sbin/milterguard
/usr/lib/systemd/system/milterguard.service
/usr/share/milterguard/tools/replay_mailbox.py
%doc /usr/share/doc/milterguard/README.md
%doc /usr/share/doc/milterguard/QUICKSTART.md
%doc /usr/share/doc/milterguard/OPERATING_GUIDE.md
%doc /usr/share/doc/milterguard/PACKAGED_INSTALL.md
%doc /usr/share/doc/milterguard/THIRD_PARTY_NOTICES.md
%doc /usr/share/doc/milterguard/THIRD_PARTY_LICENSES
%license /usr/share/doc/milterguard/LICENSE
EOF
    rpmbuild --define "_topdir $rpm_top" --define "_tmppath $rpm_top/tmp" \
        --define "_staging $payload" \
        --define '_build_id_links none' -bb "$rpm_top/SPECS/milterguard.spec"
    install -m 0644 "$rpm_top/RPMS/x86_64/milterguard-$package_version-1.x86_64.rpm" \
        "$artifacts/milterguard-$package_version-1.x86_64.rpm"
}

case "$format" in all|tar) stage_archive ;; esac
case "$format" in all|deb|rpm) stage_native_payload ;; esac
case "$format" in all|deb) build_deb ;; esac
case "$format" in all|rpm) build_rpm ;; esac

mkdir -p "$output_dir"
for artifact in "$artifacts"/*; do
    target="$output_dir/$(basename "$artifact")"
    if [ -e "$target" ]; then
        echo "Release asset already exists: $target" >&2
        exit 1
    fi
done
manifest="milterguard-$version-SHA256SUMS.txt"
if [ -e "$output_dir/$manifest" ]; then
    echo "Release manifest already exists: $output_dir/$manifest" >&2
    exit 1
fi
(cd "$artifacts" && sha256sum ./*) > "$work_dir/$manifest"
mv "$work_dir/$manifest" "$artifacts/$manifest"
for artifact in "$artifacts"/*; do
    mv "$artifact" "$output_dir/"
done
echo "Release assets written to $output_dir"
