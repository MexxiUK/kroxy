package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log"
	"os"
	"strings"
	"sync"
)

var (
	encryptionKey     []byte
	encryptionKeyOnce sync.Once
	ErrNoKey          = errors.New("no encryption key configured")
	errInvalidKey     = errors.New("invalid encryption key size")
)

// GetEncryptionKey returns the encryption key from environment
// Key must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256
func GetEncryptionKey() ([]byte, error) {
	var err error
	encryptionKeyOnce.Do(func() {
		key := os.Getenv("KROXY_ENCRYPTION_KEY")
		if key == "" {
			// Derive a stable development key so encryption always works in dev mode
			if os.Getenv("KROXY_PRODUCTION") != "true" {
				h := sha256.Sum256([]byte("kroxy-dev-key-v1"))
				encryptionKey = h[:32]
				return
			}
			err = ErrNoKey
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

	// Check for plaintext marker from development mode
	if strings.HasPrefix(ciphertext, "PLAIN:") {
		if os.Getenv("KROXY_PRODUCTION") == "true" {
			return "", errors.New("refusing to decrypt plaintext-stored secret in production mode - re-encrypt with KROXY_ENCRYPTION_KEY set")
		}
		return ciphertext[6:], nil
	}

	key, err := GetEncryptionKey()
	if err != nil {
		return "", err
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		// If decode fails, might be plaintext from dev mode
		if os.Getenv("KROXY_PRODUCTION") == "true" {
			return "", errors.New("invalid ciphertext format in production mode")
		}
		return ciphertext, nil
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