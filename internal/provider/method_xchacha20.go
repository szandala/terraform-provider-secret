package provider

import (
	"errors"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// XCHACHA20: XChaCha20-Poly1305, key from Argon2id(passphrase, salt,
// t=3, m=64 MiB, p=4) - the second recommended setting of RFC 9106.
//
//	payload = salt(16) || nonce(24) || ciphertext || Poly1305 tag(16)
//
// Compared to AES256 the cipher is not "stronger" in any practical sense
// (both are 256-bit AEADs); the gain is the KDF: Argon2id is memory-hard and
// tuned twice as expensive in memory as the AES256 scrypt setting, so brute
// forcing a weak passphrase costs more. The 192-bit random nonce also removes
// any nonce-reuse concern. Price: ~64 MiB RAM and noticeably more CPU per
// decryption, in both plan and apply.

func init() { registerMethod(xchacha20Method{}) }

type xchacha20Method struct{}

const (
	xchachaSaltLen  = 16
	xchachaNonceLen = chacha20poly1305.NonceSizeX // 24
	xchachaTagLen   = chacha20poly1305.Overhead   // 16

	xchachaArgonTime    = 3
	xchachaArgonMemory  = 64 * 1024 // KiB
	xchachaArgonThreads = 4
)

func (xchacha20Method) Name() string     { return "xchacha20" }
func (xchacha20Method) Prefix() string   { return "XCHACHA20;" }
func (xchacha20Method) Asymmetric() bool { return false }
func (xchacha20Method) Summary() string {
	return "XChaCha20-Poly1305, passphrase via Argon2id (t=3, 64 MiB, p=4). Harder to brute-force, slower."
}

func (xchacha20Method) key(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, xchachaArgonTime, xchachaArgonMemory, xchachaArgonThreads, chacha20poly1305.KeySize)
}

func (m xchacha20Method) Seal(key string, plaintext []byte) ([]byte, error) {
	if err := checkPassphrase(m, key); err != nil {
		return nil, err
	}
	salt, err := randomBytes(xchachaSaltLen)
	if err != nil {
		return nil, err
	}
	nonce, err := randomBytes(xchachaNonceLen)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(m.key(key, salt))
	if err != nil {
		return nil, err
	}
	out := append(salt, nonce...)
	return aead.Seal(out, nonce, plaintext, nil), nil
}

func (m xchacha20Method) Open(key string, payload []byte) ([]byte, error) {
	if err := checkPassphrase(m, key); err != nil {
		return nil, err
	}
	salt := payload[:xchachaSaltLen]
	nonce := payload[xchachaSaltLen : xchachaSaltLen+xchachaNonceLen]
	aead, err := chacha20poly1305.NewX(m.key(key, salt))
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, payload[xchachaSaltLen+xchachaNonceLen:], nil)
	if err != nil {
		return nil, errDecrypt
	}
	return plaintext, nil
}

func (xchacha20Method) CheckPayload(payload []byte) error {
	if len(payload) < xchachaSaltLen+xchachaNonceLen+xchachaTagLen {
		return errors.New("payload too short / corrupt")
	}
	return nil
}

func (xchacha20Method) GenerateKey() (string, string, error) {
	p, err := generatePassphrase()
	return p, "", err
}
