package config

import "testing"

func TestParseTrustedProxyCIDRs(t *testing.T) {
	t.Parallel()

	t.Run("normalizes single IP entries", func(t *testing.T) {
		t.Parallel()

		ranges, err := parseTrustedProxyCIDRs("203.0.113.10,2001:db8::1")
		if err != nil {
			t.Fatalf("parseTrustedProxyCIDRs() error = %v", err)
		}
		if len(ranges) != 2 {
			t.Fatalf("len(ranges) = %d, want 2", len(ranges))
		}
		if got := ranges[0].String(); got != "203.0.113.10/32" {
			t.Fatalf("ranges[0] = %q, want %q", got, "203.0.113.10/32")
		}
		if got := ranges[1].String(); got != "2001:db8::1/128" {
			t.Fatalf("ranges[1] = %q, want %q", got, "2001:db8::1/128")
		}
	})

	t.Run("accepts explicit CIDRs", func(t *testing.T) {
		t.Parallel()

		ranges, err := parseTrustedProxyCIDRs("10.0.0.0/8, 192.168.0.0/16")
		if err != nil {
			t.Fatalf("parseTrustedProxyCIDRs() error = %v", err)
		}
		if len(ranges) != 2 {
			t.Fatalf("len(ranges) = %d, want 2", len(ranges))
		}
	})

	t.Run("rejects invalid entries", func(t *testing.T) {
		t.Parallel()

		if _, err := parseTrustedProxyCIDRs("10.0.0.0/8,not-a-cidr"); err == nil {
			t.Fatal("expected error for invalid trusted proxy entry")
		}
	})
}
