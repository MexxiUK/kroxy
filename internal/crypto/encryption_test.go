package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"testing"
)

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	os.Unsetenv("KROXY_PRODUCTION")
	ResetEncryptionKeyForTest()
	defer os.Unsetenv("KROXY_ENCRYPTION_KEY")

	plaintext := "sensitive-data-that-needs-protection"
	ciphertext, err := Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if ciphertext == "" {
		t.Fatal("Expected non-empty ciphertext")
	}
	if ciphertext == plaintext {
		t.Fatal("Ciphertext should not equal plaintext")
	}

	decrypted, err := Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if decrypted != plaintext {
		t.Fatalf("Expected %q, got %q", plaintext, decrypted)
	}
}

func TestEncryptDecrypt_EmptyString(t *testing.T) {
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	os.Unsetenv("KROXY_PRODUCTION")
	ResetEncryptionKeyForTest()
	defer os.Unsetenv("KROXY_ENCRYPTION_KEY")

	// Encrypt empty string should return empty
	ciphertext, err := Encrypt("")
	if err != nil {
		t.Fatalf("Encrypt(\"\") failed: %v", err)
	}
	if ciphertext != "" {
		t.Fatalf("Expected empty ciphertext for empty input, got %q", ciphertext)
	}

	// Decrypt empty string should return empty
	decrypted, err := Decrypt("")
	if err != nil {
		t.Fatalf("Decrypt(\"\") failed: %v", err)
	}
	if decrypted != "" {
		t.Fatalf("Expected empty plaintext for empty input, got %q", decrypted)
	}
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	os.Unsetenv("KROXY_PRODUCTION")
	ResetEncryptionKeyForTest()
	defer os.Unsetenv("KROXY_ENCRYPTION_KEY")

	plaintext := "tamper-test"
	ciphertext, _ := Encrypt(plaintext)

	// Tamper with the last byte, flipping it to a character different from the original.
	last := ciphertext[len(ciphertext)-1]
	tamperedChar := byte('X')
	if last == 'X' {
		tamperedChar = 'Y'
	}
	tampered := ciphertext[:len(ciphertext)-1] + string(tamperedChar)
	_, err := Decrypt(tampered)
	if err == nil {
		t.Fatal("Expected Decrypt to fail on tampered ciphertext")
	}
}

func TestDecrypt_InvalidBase64(t *testing.T) {
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	os.Unsetenv("KROXY_PRODUCTION")
	ResetEncryptionKeyForTest()
	defer os.Unsetenv("KROXY_ENCRYPTION_KEY")

	_, err := Decrypt("!!!not-valid-base64!!!")
	if err == nil {
		t.Fatal("Expected Decrypt to fail on invalid base64")
	}
}

func TestDecrypt_CiphertextTooShort(t *testing.T) {
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	os.Unsetenv("KROXY_PRODUCTION")
	ResetEncryptionKeyForTest()
	defer os.Unsetenv("KROXY_ENCRYPTION_KEY")

	// base64 encoded single byte — too short for any nonce
	_, err := Decrypt(base64.StdEncoding.EncodeToString([]byte{0x01}))
	if err == nil {
		t.Fatal("Expected Decrypt to fail on too-short ciphertext")
	}
}

func TestGetEncryptionKey_ValidKey(t *testing.T) {
	validKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_ENCRYPTION_KEY", validKey)
	os.Unsetenv("KROXY_PRODUCTION")
	ResetEncryptionKeyForTest()
	defer os.Unsetenv("KROXY_ENCRYPTION_KEY")

	key, err := GetEncryptionKey()
	if err != nil {
		t.Fatalf("GetEncryptionKey failed: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("Expected key length 32, got %d", len(key))
	}
}

func TestGetEncryptionKey_InvalidKeySize(t *testing.T) {
	// 20 bytes is not valid for AES (must be 16, 24, or 32)
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(make([]byte, 20)))
	os.Unsetenv("KROXY_PRODUCTION")
	ResetEncryptionKeyForTest()
	defer os.Unsetenv("KROXY_ENCRYPTION_KEY")

	_, err := GetEncryptionKey()
	if err == nil {
		t.Fatal("Expected GetEncryptionKey to fail with invalid key size")
	}
}

func TestGetEncryptionKey_ProductionRequired(t *testing.T) {
	os.Unsetenv("KROXY_ENCRYPTION_KEY")
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_PRODUCTION", "true")
	ResetEncryptionKeyForTest()
	defer os.Unsetenv("KROXY_PRODUCTION")

	_, err := GetEncryptionKey()
	if err == nil {
		t.Fatal("Expected GetEncryptionKey to fail in production without key")
	}
	if err != ErrNoKey {
		t.Fatalf("Expected ErrNoKey, got %v", err)
	}
}

func TestIsEncryptionAvailable(t *testing.T) {
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	os.Unsetenv("KROXY_PRODUCTION")
	ResetEncryptionKeyForTest()
	defer os.Unsetenv("KROXY_ENCRYPTION_KEY")

	if !IsEncryptionAvailable() {
		t.Fatal("Expected IsEncryptionAvailable to be true with valid key")
	}
}

func TestIsEncryptionAvailable_NotAvailable(t *testing.T) {
	os.Unsetenv("KROXY_ENCRYPTION_KEY")
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_PRODUCTION", "true")
	ResetEncryptionKeyForTest()
	defer os.Unsetenv("KROXY_PRODUCTION")

	if IsEncryptionAvailable() {
		t.Fatal("Expected IsEncryptionAvailable to be false without key in production")
	}
}

func TestGetBackupHMACKey_DerivedAndStable(t *testing.T) {
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	os.Unsetenv("KROXY_PRODUCTION")
	ResetEncryptionKeyForTest()
	ResetBackupHMACKeyForTest()
	defer os.Unsetenv("KROXY_ENCRYPTION_KEY")

	encKey, err := GetEncryptionKey()
	if err != nil {
		t.Fatalf("GetEncryptionKey failed: %v", err)
	}

	derived1, err := GetBackupHMACKey()
	if err != nil {
		t.Fatalf("GetBackupHMACKey failed: %v", err)
	}
	if len(derived1) != sha256.Size {
		t.Fatalf("expected derived key length %d, got %d", sha256.Size, len(derived1))
	}
	if string(derived1) == string(encKey) {
		t.Errorf("backup HMAC key must differ from the encryption key")
	}

	derived2, err := GetBackupHMACKey()
	if err != nil {
		t.Fatalf("GetBackupHMACKey second call failed: %v", err)
	}
	if string(derived1) != string(derived2) {
		t.Errorf("backup HMAC key must be deterministic")
	}
}

func TestLoadOrGenerateDevKey(t *testing.T) {
	os.Unsetenv("KROXY_ENCRYPTION_KEY")
	os.Unsetenv("KROXY_PRODUCTION")
	ResetEncryptionKeyForTest()

	// Use a temp directory so we don't pollute the repo
	tmpDir := t.TempDir()
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_DATA_DIR", tmpDir)
	defer os.Unsetenv("KROXY_DATA_DIR")

	key1, err := loadOrGenerateDevKey()
	if err != nil {
		t.Fatalf("loadOrGenerateDevKey failed: %v", err)
	}
	if len(key1) != 32 {
		t.Fatalf("Expected 32-byte key, got %d", len(key1))
	}

	// Second call should read the same key from file
	key2, err := loadOrGenerateDevKey()
	if err != nil {
		t.Fatalf("loadOrGenerateDevKey second call failed: %v", err)
	}
	if string(key1) != string(key2) {
		t.Fatal("Expected same key on second load")
	}
}
