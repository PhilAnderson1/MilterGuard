package config

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/netsafety"
)

// MilterSocketAddress is the validated network and address used for the
// configured Milter listener.
type MilterSocketAddress struct {
	Network string
	Address string
}

// ParseMilterSocket validates the supported Milter listener syntax without
// resolving hostnames or checking whether the address is currently available.
func ParseMilterSocket(value string) (MilterSocketAddress, error) {
	switch {
	case strings.HasPrefix(value, "unix:"):
		path := strings.TrimPrefix(value, "unix:")
		if path == "" || strings.ContainsRune(path, '\x00') {
			return MilterSocketAddress{}, fmt.Errorf("milter.socket requires a valid Unix socket path after unix:")
		}
		return MilterSocketAddress{Network: "unix", Address: path}, nil
	case strings.HasPrefix(value, "tcp:"):
		address := strings.TrimPrefix(value, "tcp:")
		host, portText, err := net.SplitHostPort(address)
		if err != nil {
			return MilterSocketAddress{}, fmt.Errorf("milter.socket requires a TCP address in host:port form: %w", err)
		}
		if host != "" {
			if _, err := netip.ParseAddr(host); err != nil && netsafety.DNSHostname(host) == "" {
				return MilterSocketAddress{}, fmt.Errorf("milter.socket contains an invalid TCP host %q", host)
			}
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return MilterSocketAddress{}, fmt.Errorf("milter.socket TCP port must be between 1 and 65535")
		}
		return MilterSocketAddress{Network: "tcp", Address: address}, nil
	default:
		return MilterSocketAddress{}, fmt.Errorf("milter.socket must begin with unix: or tcp:")
	}
}
