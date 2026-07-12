package totp

import (
	"crypto/subtle"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// GenerateSecret creates a new TOTP secret and returns the base32 secret
// and the otpauth:// URI for QR code generation. SHA-256 is used instead of
// SHA-1 to align with modern TOTP recommendations.
func GenerateSecret(issuer, accountName string) (secret string, uri string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA256,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// ValidateCode checks a TOTP code against the given secret with a 1-period skew
// for clock drift tolerance. Uses constant-time comparison internally.
func ValidateCode(secret, code string) bool {
	ok, _ := totp.ValidateCustom(
		code,
		secret,
		time.Now().UTC(),
		totp.ValidateOpts{
			Period:    30,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA256,
			Skew:      1,
		},
	)
	return ok
}

// ValidateCodeExact validates without skew (for setup verification).
func ValidateCodeExact(secret, code string) bool {
	ok, _ := totp.ValidateCustom(
		code,
		secret,
		time.Now().UTC(),
		totp.ValidateOpts{
			Period:    30,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA256,
			Skew:      0,
		},
	)
	return ok
}

// ConstantTimeEqual compares two strings in constant time.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// GenerateURI builds the otpauth:// TOTP URI from the raw secret.
func GenerateURI(issuer, accountName, secret string) (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
		Secret:      []byte(secret),
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA256,
	})
	if err != nil {
		return "", err
	}
	return key.URL(), nil
}
