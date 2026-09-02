package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func reqWith(remoteAddr, xff string) echo.Context {
	e := echo.New()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remoteAddr
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return e.NewContext(r, httptest.NewRecorder())
}

// TestRequestInfoTrustedProxies pins the client-IP contract: XFF is honored
// only when the direct peer is configured; untrusted peers cannot forge an
// IP to rotate past rate limits.
func TestRequestInfoTrustedProxies(t *testing.T) {
	reset := func(list []string) func() {
		old := trustedProxies
		SetTrustedProxies(list)
		return func() { trustedProxies = old }
	}

	// Untrusted peer: XFF ignored.
	t.Cleanup(reset(nil))
	_, ip := requestInfo(reqWith("203.0.113.9:44321", "1.2.3.4, 10.0.0.1"))
	if ip != "203.0.113.9" {
		t.Fatalf("untrusted peer: ip = %s, want the direct peer", ip)
	}

	// Trusted exact IP: first XFF hop wins.
	t.Cleanup(reset([]string{"10.0.0.1"}))
	_, ip = requestInfo(reqWith("10.0.0.1:44321", "198.51.100.7, 10.0.0.2"))
	if ip != "198.51.100.7" {
		t.Fatalf("trusted peer: ip = %s, want first XFF hop", ip)
	}

	// Trusted CIDR.
	t.Cleanup(reset([]string{"10.0.0.0/8"}))
	_, ip = requestInfo(reqWith("10.1.2.3:9999", "198.51.100.8"))
	if ip != "198.51.100.8" {
		t.Fatalf("trusted cidr: ip = %s, want first XFF hop", ip)
	}

	// Trusted peer but malformed XFF: fall back to the peer itself.
	t.Cleanup(reset([]string{"10.0.0.0/8"}))
	_, ip = requestInfo(reqWith("10.1.2.3:9999", "  "))
	if ip != "10.1.2.3" {
		t.Fatalf("blank XFF: ip = %s, want peer", ip)
	}

	// IPv6 loopback peer.
	t.Cleanup(reset(nil))
	_, ip = requestInfo(reqWith("[::1]:5555", ""))
	if ip != "::1" {
		t.Fatalf("ipv6 peer: ip = %s, want ::1", ip)
	}
}
