package totp

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func TestGenerateSecret(t *testing.T) {
	secret, uri, err := GenerateSecret("Kroxy", "admin@example.com")
	if err != nil {
		t.Fatalf("GenerateSecret failed: %v", err)
	}
	if secret == "" {
		t.Fatal("Expected non-empty secret")
	}
	if uri == "" {
		t.Fatal("Expected non-empty URI")
	}

	// URI should contain otpauth://totp/
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Fatalf("URI should start with otpauth://totp/, got %q", uri)
	}

	// Secret should be valid base32
	if strings.Contains(secret, " ") {
		t.Fatal("Secret should not contain spaces")
	}
}

func TestGenerateSecret_DifferentAccounts(t *testing.T) {
	secret1, uri1, err1 := GenerateSecret("Kroxy", "user1@example.com")
	secret2, uri2, err2 := GenerateSecret("Kroxy", "user2@example.com")

	if err1 != nil || err2 != nil {
		t.Fatalf("GenerateSecret failed: %v, %v", err1, err2)
	}

	// Different accounts should get different secrets
	if secret1 == secret2 {
		t.Fatal("Different accounts should have different secrets")
	}
	if uri1 == uri2 {
		t.Fatal("Different accounts should have different URIs")
	}
}

func TestValidateCode_Valid(t *testing.T) {
	secret, _, err := GenerateSecret("Kroxy", "test@example.com")
	if err != nil {
		t.Fatalf("GenerateSecret failed: %v", err)
	}

	code, err := totp.GenerateCodeCustom(secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA256,
		Skew:      0,
	})
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}

	if !ValidateCode(secret, code) {
		t.Fatalf("ValidateCode should succeed for freshly generated code")
	}
}

func TestValidateCode_Invalid(t *testing.T) {
	secret, _, err := GenerateSecret("Kroxy", "test@example.com")
	if err != nil {
		t.Fatalf("GenerateSecret failed: %v", err)
	}

	if ValidateCode(secret, "000000") {
		t.Fatal("ValidateCode should fail for wrong code")
	}
}

func TestValidateCode_WrongSecret(t *testing.T) {
	secret1, _, _ := GenerateSecret("Kroxy", "user1@example.com")
	secret2, _, _ := GenerateSecret("Kroxy", "user2@example.com")

	code, _ := totp.GenerateCode(secret1, time.Now().UTC())

	if ValidateCode(secret2, code) {
		t.Fatal("ValidateCode should fail for code generated with different secret")
	}
}

func TestValidateCode_TimeSkew(t *testing.T) {
	secret, _, err := GenerateSecret("Kroxy", "test@example.com")
	if err != nil {
		t.Fatalf("GenerateSecret failed: %v", err)
	}

	// Generate code for 30 seconds in the past (1 period skew)
	past := time.Now().UTC().Add(-30 * time.Second)
	code, err := totp.GenerateCodeCustom(secret, past, totp.ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA256,
		Skew:      0,
	})
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}

	// Should still validate with Skew=1
	if !ValidateCode(secret, code) {
		t.Fatal("ValidateCode should accept code from 1 period ago (skew tolerance)")
	}

	// Generate code for 90 seconds in the past (3 periods — beyond skew)
	old := time.Now().UTC().Add(-90 * time.Second)
	oldCode, err := totp.GenerateCodeCustom(secret, old, totp.ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA256,
		Skew:      0,
	})
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}

	// Should NOT validate (beyond 1-period skew)
	if ValidateCode(secret, oldCode) {
		t.Fatal("ValidateCode should reject code from 3 periods ago")
	}
}

func TestValidateCodeExact_Valid(t *testing.T) {
	secret, _, err := GenerateSecret("Kroxy", "test@example.com")
	if err != nil {
		t.Fatalf("GenerateSecret failed: %v", err)
	}

	code, err := totp.GenerateCodeCustom(secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA256,
		Skew:      0,
	})
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}

	if !ValidateCodeExact(secret, code) {
		t.Fatal("ValidateCodeExact should succeed for current-period code")
	}
}

func TestValidateCodeExact_NoSkew(t *testing.T) {
	secret, _, err := GenerateSecret("Kroxy", "test@example.com")
	if err != nil {
		t.Fatalf("GenerateSecret failed: %v", err)
	}

	// Generate code for 30 seconds in the past
	past := time.Now().UTC().Add(-30 * time.Second)
	code, err := totp.GenerateCodeCustom(secret, past, totp.ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA256,
		Skew:      0,
	})
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}

	// ValidateCodeExact has Skew=0, so this should fail
	if ValidateCodeExact(secret, code) {
		t.Fatal("ValidateCodeExact should reject code from previous period (no skew)")
	}
}

func TestValidateCodeExact_Invalid(t *testing.T) {
	secret, _, _ := GenerateSecret("Kroxy", "test@example.com")

	if ValidateCodeExact(secret, "000000") {
		t.Fatal("ValidateCodeExact should fail for wrong code")
	}
}

func TestConstantTimeEqual(t *testing.T) {
	if !ConstantTimeEqual("same", "same") {
		t.Fatal("ConstantTimeEqual should return true for identical strings")
	}
	if ConstantTimeEqual("same", "different") {
		t.Fatal("ConstantTimeEqual should return false for different strings")
	}
	if !ConstantTimeEqual("", "") {
		t.Fatal("ConstantTimeEqual should return true for two empty strings")
	}
}
