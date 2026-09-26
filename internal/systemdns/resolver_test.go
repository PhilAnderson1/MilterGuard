package systemdns

import (
	"net"
	"testing"
)

func TestNewResolverIsIndependentOfDefaultResolver(t *testing.T) {
	originalStrictErrors := net.DefaultResolver.StrictErrors
	net.DefaultResolver.StrictErrors = true
	t.Cleanup(func() { net.DefaultResolver.StrictErrors = originalStrictErrors })

	first := NewResolver()
	second := NewResolver()
	if first == net.DefaultResolver || second == net.DefaultResolver {
		t.Fatal("new resolver aliases net.DefaultResolver")
	}
	if first == second {
		t.Fatal("NewResolver returned a shared resolver")
	}
	if first.StrictErrors || second.StrictErrors {
		t.Fatal("new resolver inherited net.DefaultResolver.StrictErrors")
	}
}
