package dto

import "testing"

func TestMaskIP(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"ipv4", "192.168.1.100", "192.168.1.0"},
		{"ipv4_last", "10.0.0.1", "10.0.0.0"},
		{"ipv6", "2001:db8::1", "***"},
		{"ipv6_loopback", "::1", "***"},
		{"empty", "", ""},
		{"invalid", "not-an-ip", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MaskIP(tt.input)
			if got != tt.expected {
				t.Fatalf("MaskIP(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
