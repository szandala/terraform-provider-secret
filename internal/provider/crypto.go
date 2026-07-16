package provider

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/scrypt"
)

// Wire format: "SECRET1;" + base64( salt(16) || nonce(12) || ciphertext+tag )
//
// Key derivation: scrypt(passphrase, salt, N=2^15, r=8, p=1) -> 32 bytes (AES-256).
// AEAD: AES-256-GCM. GCM tag is appended to ciphertext by Seal (standard Go behaviour)

const (
	magicPrefix = "SECRET1;"
	saltLen     = 16
	nonceLen    = 12
	keyLen      = 32

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

// Encrypt turns plaintext into the "SECRET1;..." wire string.
// Used by the CLI helper (cmd/secret-encrypt), not by the provider at runtime.
func Encrypt(passphrase, plaintext string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := deriveKey(passphrase, salt)
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
	if !strings.HasPrefix(wire, magicPrefix) {
		return "", fmt.Errorf("ciphertext missing %q prefix", magicPrefix)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(wire, magicPrefix))
	if err != nil {
		return "", fmt.Errorf("invalid base64 payload: %w", err)
	}
	if len(raw) < saltLen+nonceLen+16 { // 16 = min GCM tag
		return "", errors.New("payload too short / corrupt")
	}
	salt := raw[:saltLen]
	nonce := raw[saltLen : saltLen+nonceLen]
	sealed := raw[saltLen+nonceLen:]

	key, err := deriveKey(passphrase, salt)
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
	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		// Wrong key or tampered ciphertext both land here
		return "", errors.New("decryption failed: wrong key or corrupted ciphertext")
	}
	return string(plaintext), nil
}
