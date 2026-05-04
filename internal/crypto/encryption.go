package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	encryptionKey     []byte
	encryptionKeyOnce sync.Once
	ErrNoKey          = errors.New("no encryption key configured")
	errInvalidKey     = errors.New("invalid encryption key size")
)

// devKeyPath returns the path for the auto-generated development encryption key file.
func devKeyPath() string {
	dataDir := os.Getenv("KROXY_DATA_DIR")
	if dataDir == "" {
		dataDir = "."
	}
	return filepath.Join(dataDir, ".kroxy-encryption-key")
}

// loadOrGenerateDevKey generates a random 32-byte key for development use
// and persists it to a file with restricted permissions (0600).
// This replaces the previous hardcoded dev key (CRIT-002).
func loadOrGenerateDevKey() ([]byte, error) {
	keyPath := devKeyPath()

	// If a key file already exists, read it
	if data, err := os.ReadFile(keyPath); err == nil {
		keyBytes, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if decodeErr == nil && (len(keyBytes) == 16 || len(keyBytes) == 24 || len(keyBytes) == 32) {
			return keyBytes, nil
		}
		// Invalid file content - fall through to regenerate
		log.Printf("WARNING: existing dev key file %s is invalid, regenerating", keyPath)
	}

	// Generate a random 32-byte key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("failed to generate dev encryption key: %w", err)
	}

	// Persist with 0600 permissions
	keyDir := filepath.Dir(keyPath)
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create key directory: %w", err)
	}
	encodedKey := base64.StdEncoding.EncodeToString(keyBytes)
	if err := os.WriteFile(keyPath, []byte(encodedKey+"\n"), 0600); err != nil {
		return nil, fmt.Errorf("failed to write dev encryption key: %w", err)
	}

	log.Printf("WARNING: generated development encryption key at %s. Set KROXY_ENCRYPTION_KEY for production.", keyPath)
	return keyBytes, nil
}

// GetEncryptionKey returns the encryption key from environment.
// Key must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256.
// In non-production mode without KROXY_ENCRYPTION_KEY set, a random dev key
// is generated once and persisted to a file (CRIT-002 fix).
func GetEncryptionKey() ([]byte, error) {
	var err error
	encryptionKeyOnce.Do(func() {
		key := os.Getenv("KROXY_ENCRYPTION_KEY")
		if key == "" {
			if os.Getenv("KROXY_PRODUCTION") == "true" {
				err = ErrNoKey
				return
			}
			// Dev mode: generate and persist a random key instead of using a hardcoded one
			encryptionKey, err = loadOrGenerateDevKey()
			return
		}

		// Decode base64 key
		keyBytes, decodeErr := base64.StdEncoding.DecodeString(key)
		if decodeErr != nil {
			err = decodeErr
			return
		}

		// Validate key size
		if len(keyBytes) != 16 && len(keyBytes) != 24 && len(keyBytes) != 32 {
			err = errInvalidKey
			return
		}

		encryptionKey = keyBytes
	})

	return encryptionKey, err
}

// IsEncryptionAvailable returns true if encryption key is configured
func IsEncryptionAvailable() bool {
	_, err := GetEncryptionKey()
	return err == nil
}

// RequireEncryptionInProduction logs a warning if encryption is not configured in production
func RequireEncryptionInProduction() {
	if os.Getenv("KROXY_PRODUCTION") == "true" {
		if !IsEncryptionAvailable() {
			log.Println("WARNING: KROXY_ENCRYPTION_KEY not set in production mode. Secrets will be stored in plaintext.")
			log.Println("WARNING: Set KROXY_ENCRYPTION_KEY for secure storage of OIDC client secrets.")
			log.Println("WARNING: Generate a key with: openssl rand -base64 32")
		}
	}
}

// Encrypt encrypts plaintext using AES-GCM
func Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	key, err := GetEncryptionKey()
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts ciphertext using AES-GCM
func Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	key, err := GetEncryptionKey()
	if err != nil {
		return "", err
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", errors.New("invalid ciphertext format")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, encryptedData := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
