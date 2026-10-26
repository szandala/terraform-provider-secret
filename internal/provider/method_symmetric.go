package provider

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// Helpers shared by passphrase-based (symmetric) methods.

// Full-form age X25519 keys (bech32: "1" separator + 58 data/checksum chars).
var (
	agePublicKeyRe  = regexp.MustCompile(`^age1[02-9ac-hj-np-z]{58}$`)
	agePrivateKeyRe = regexp.MustCompile(`^AGE-SECRET-KEY-1[02-9AC-HJ-NP-Z]{58}$`)
)

// keyTokens splits a key env var into tokens: whitespace or comma separated,
// lines starting with '#' ignored (so `secret-encrypt --genkey` output works as is).
func keyTokens(key string) []string {
	var out []string
	for _, line := range strings.Split(key, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		out = append(out, strings.FieldsFunc(line, func(r rune) bool { return unicode.IsSpace(r) || r == ',' })...)
	}
	return out
}

func looksLikeAgeKey(key string) bool {
	for _, t := range keyTokens(key) {
		if agePublicKeyRe.MatchString(t) || agePrivateKeyRe.MatchString(t) {
			return true
		}
	}
	return false
}

// checkPassphrase catches the most common mix-up: an age key in the env var
// while encrypting/decrypting with a passphrase method.
func checkPassphrase(m Method, key string) error {
	if looksLikeAgeKey(key) {
		return fmt.Errorf("the key looks like an age key, but %s uses a passphrase; for age keys use --method age1", m.Prefix())
	}
	return nil
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// generatePassphrase returns 32 random bytes as URL-safe base64 (43 chars).
func generatePassphrase() (string, error) {
	b, err := randomBytes(32)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// errDecrypt is the only error a symmetric Open returns for a wrong key or a
// tampered payload: the two must not be distinguishable.
var errDecrypt = errors.New("decryption failed: wrong key or corrupted ciphertext")
