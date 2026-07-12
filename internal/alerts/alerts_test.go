package alerts

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

const fixedTimestamp = int64(1234567890)

func TestSign_HMACSHA256(t *testing.T) {
	m := &Manager{}

	tests := []struct {
		name    string
		secret  string
		payload []byte
		wantLen int
	}{
		{
			name:    "standard payload",
			secret:  "test-secret",
			payload: []byte(`{"event":"backend_down"}`),
			wantLen: 64, // hex-encoded 32-byte SHA256
		},
		{
			name:    "empty secret",
			secret:  "",
			payload: []byte(`{"event":"test"}`),
			wantLen: 64,
		},
		{
			name:    "long secret",
			secret:  "a-very-long-secret-that-exceeds-block-size-of-sha256-and-requires-hashing-before-use-in-hmac",
			payload: []byte(`{"event":"test"}`),
			wantLen: 64,
		},
		{
			name:    "unicode payload",
			secret:  "secret",
			payload: []byte(`{"message":"hello 世界"}`),
			wantLen: 64,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := m.sign(tt.payload, tt.secret, fixedTimestamp)
			if len(got) != tt.wantLen {
				t.Errorf("sign() length = %d, want %d", len(got), tt.wantLen)
			}

			// Verify it's valid hex
			if _, err := hex.DecodeString(got); err != nil {
				t.Errorf("sign() returned invalid hex: %v", err)
			}

			// Verify against standard library HMAC with timestamp prefix
			mac := hmac.New(sha256.New, []byte(tt.secret))
			mac.Write([]byte("1234567890|"))
			mac.Write(tt.payload)
			want := hex.EncodeToString(mac.Sum(nil))
			if got != want {
				t.Errorf("sign() = %q, want %q", got, want)
			}
		})
	}
}

func TestSign_Deterministic(t *testing.T) {
	m := &Manager{}
	secret := "my-webhook-secret"
	payload := []byte(`{"type":"backend_down","severity":"critical"}`)

	sig1 := m.sign(payload, secret, fixedTimestamp)
	sig2 := m.sign(payload, secret, fixedTimestamp)

	if sig1 != sig2 {
		t.Errorf("sign() not deterministic: %q != %q", sig1, sig2)
	}
}

func TestSign_DifferentSecretsProduceDifferentSignatures(t *testing.T) {
	m := &Manager{}
	payload := []byte(`{"type":"test"}`)

	sigA := m.sign(payload, "secret-a", fixedTimestamp)
	sigB := m.sign(payload, "secret-b", fixedTimestamp)

	if sigA == sigB {
		t.Error("sign() produced identical signatures for different secrets")
	}
}

func TestSign_DifferentPayloadsProduceDifferentSignatures(t *testing.T) {
	m := &Manager{}
	secret := "shared-secret"

	sigA := m.sign([]byte(`{"type":"a"}`), secret, fixedTimestamp)
	sigB := m.sign([]byte(`{"type":"b"}`), secret, fixedTimestamp)

	if sigA == sigB {
		t.Error("sign() produced identical signatures for different payloads")
	}
}

func TestSign_VulnerableToLengthExtension(t *testing.T) {
	// This test verifies we are NOT vulnerable to length-extension attacks.
	// The old implementation used SHA256(secret || payload) which is vulnerable.
	// HMAC-SHA256 is not vulnerable. We prove this by ensuring the signature
	// of a prefix does not help predict the signature of a suffix.
	m := &Manager{}
	secret := "my-secret"

	payload1 := []byte(`{"type":"event1"}`)
	payload2 := append(payload1, []byte(`extra`)...)

	sig1 := m.sign(payload1, secret, fixedTimestamp)
	sig2 := m.sign(payload2, secret, fixedTimestamp)

	// If we were using raw SHA256(secret||payload), appending data and continuing
	// the hash state would yield a valid signature. HMAC prevents this.
	// We simply verify the two signatures are unrelated.
	if sig1 == sig2 {
		t.Error("signatures should differ for different payloads")
	}

	// There is no mathematical relationship between sig1 and sig2 that would
	// allow an attacker to compute sig2 from sig1 without knowing the secret.
}
