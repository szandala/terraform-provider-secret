package provider

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/scrypt"
)

// Wire format: "SECRET1;" + base64( salt(16) || nonce(12) || ciphertext+tag )
//
// Key derivation: scrypt(passphrase, salt, N=2^15, r=8, p=1) -> 32 bytes (AES-256).
// AEAD: AES-256-GCM. GCM tag is appended to ciphertext by Seal (standard Go behavior).
//
// The salt is authenticated implicitly (a different salt derives a different key)
// and the nonce is authenticated by GCM, so any tampering fails in gcm.Open.
//
// Whitespace anywhere in the wire string is ignored, so a value can be wrapped
// across lines, indented in a heredoc, or loaded with file() (trailing newline).

const (
	magicPrefix = "SECRET1;"
	saltLen     = 16
	nonceLen    = 12
	keyLen      = 32
	gcmTagLen   = 16

	scryptN = 1 << 15
	scryptR = 8
	scryptP = 1
)

func deriveKey(passphrase string, salt []byte) ([]byte, error) {
	if passphrase == "" {
		return nil, errors.New("empty passphrase")
	}
	return scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, keyLen)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// NormalizeCiphertext removes all whitespace from a wire string.
func NormalizeCiphertext(wire string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, wire)
}

// WrapCiphertext splits a wire string into lines of at most width characters,
// like ansible-vault does, so encrypted files diff nicely. width <= 0 disables it.
func WrapCiphertext(wire string, width int) string {
	wire = NormalizeCiphertext(wire)
	if width <= 0 || len(wire) <= width {
		return wire
	}
	var b strings.Builder
	for len(wire) > width {
		b.WriteString(wire[:width])
		b.WriteByte('\n')
		wire = wire[width:]
	}
	b.WriteString(wire)
	return b.String()
}

// parseWire checks the format and splits the payload. It needs no key, so it is
// also used to validate configuration before any passphrase is available.
func parseWire(wire string) (salt, nonce, sealed []byte, err error) {
	wire = NormalizeCiphertext(wire)
	if !strings.HasPrefix(wire, magicPrefix) {
		return nil, nil, nil, fmt.Errorf("ciphertext missing %q prefix", magicPrefix)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(wire, magicPrefix))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid base64 payload: %w", err)
	}
	if len(raw) < saltLen+nonceLen+gcmTagLen {
		return nil, nil, nil, errors.New("payload too short / corrupt")
	}
	return raw[:saltLen], raw[saltLen : saltLen+nonceLen], raw[saltLen+nonceLen:], nil
}

// ValidateCiphertext reports whether wire is structurally valid (no decryption).
func ValidateCiphertext(wire string) error {
	_, _, _, err := parseWire(wire)
	return err
}

// Encrypt turns plaintext into the "SECRET1;..." wire string.
// Used by the CLI helper (cmd/secret-encrypt), not by the provider at runtime.
func Encrypt(passphrase, plaintext string) (string, error) {
	if !utf8.ValidString(plaintext) {
		// Terraform strings must be UTF-8; such a value could never be decrypted
		// into an attribute, so refuse early instead of at plan time.
		return "", errors.New("plaintext is not valid UTF-8; base64-encode binary data before encrypting")
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := deriveKey(passphrase, salt)
	if err != nil {
		return "", err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	payload := make([]byte, 0, saltLen+nonceLen+len(sealed))
	payload = append(payload, salt...)
	payload = append(payload, nonce...)
	payload = append(payload, sealed...)

	return magicPrefix + base64.StdEncoding.EncodeToString(payload), nil
}

// Decrypt reverses Encrypt. This is what the provider calls in Open().
func Decrypt(passphrase, wire string) (string, error) {
	salt, nonce, sealed, err := parseWire(wire)
	if err != nil {
		return "", err
	}
	key, err := deriveKey(passphrase, salt)
	if err != nil {
		return "", err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		// Wrong key or tampered ciphertext both land here.
		return "", errors.New("decryption failed: wrong key or corrupted ciphertext")
	}
	if !utf8.Valid(plaintext) {
		return "", errors.New("decrypted value is not valid UTF-8; Terraform strings must be UTF-8 (base64-encode binary data before encrypting)")
	}
	return string(plaintext), nil
}

// WriteOnlyVersion derives a stable, positive integer from a ciphertext, for use
// as a *_wo_version argument. It changes whenever the ciphertext changes (i.e.
// whenever the secret is re-encrypted) and ignores whitespace/wrapping. It hashes
// the ciphertext only, so it reveals nothing about the plaintext.
func WriteOnlyVersion(wire string) int64 {
	sum := sha256.Sum256([]byte(NormalizeCiphertext(wire)))
	// 53 bits: exactly representable as a float64/JSON number, always > 0.
	v := int64(binary.BigEndian.Uint64(sum[:8]) >> 11)
	if v == 0 {
		v = 1
	}
	return v
}
