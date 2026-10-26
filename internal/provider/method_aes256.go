package provider

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"golang.org/x/crypto/scrypt"
)

// AES256: AES-256-GCM, key from scrypt(passphrase, salt, N=2^15, r=8, p=1).
//
//	payload = salt(16) || nonce(12) || ciphertext || GCM tag(16)
//
// The salt is authenticated implicitly (another salt derives another key) and
// the nonce by GCM, so any tampering fails in Open.
//
// "SECRET1;" is the old name of exactly this format and is still decrypted.

func init() { registerMethod(aes256Method{}, "SECRET1;") }

type aes256Method struct{}

const (
	aes256SaltLen  = 16
	aes256NonceLen = 12
	aes256TagLen   = 16

	aes256ScryptN = 1 << 15
	aes256ScryptR = 8
	aes256ScryptP = 1
)

func (aes256Method) Name() string     { return "aes256" }
func (aes256Method) Prefix() string   { return "AES256;" }
func (aes256Method) Asymmetric() bool { return false }
func (aes256Method) Summary() string {
	return "AES-256-GCM, passphrase via scrypt (N=2^15, 32 MiB). Default."
}

func (m aes256Method) aead(passphrase string, salt []byte) (cipher.AEAD, error) {
	key, err := scrypt.Key([]byte(passphrase), salt, aes256ScryptN, aes256ScryptR, aes256ScryptP, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (m aes256Method) Seal(key string, plaintext []byte) ([]byte, error) {
	if err := checkPassphrase(m, key); err != nil {
		return nil, err
	}
	salt, err := randomBytes(aes256SaltLen)
	if err != nil {
		return nil, err
	}
	nonce, err := randomBytes(aes256NonceLen)
	if err != nil {
		return nil, err
	}
	aead, err := m.aead(key, salt)
	if err != nil {
		return nil, err
	}
	out := append(salt, nonce...)
	return aead.Seal(out, nonce, plaintext, nil), nil
}

func (m aes256Method) Open(key string, payload []byte) ([]byte, error) {
	if err := checkPassphrase(m, key); err != nil {
		return nil, err
	}
	salt := payload[:aes256SaltLen]
	nonce := payload[aes256SaltLen : aes256SaltLen+aes256NonceLen]
	aead, err := m.aead(key, salt)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, payload[aes256SaltLen+aes256NonceLen:], nil)
	if err != nil {
		return nil, errDecrypt
	}
	return plaintext, nil
}

func (aes256Method) CheckPayload(payload []byte) error {
	if len(payload) < aes256SaltLen+aes256NonceLen+aes256TagLen {
		return errors.New("payload too short / corrupt")
	}
	return nil
}

func (aes256Method) GenerateKey() (string, string, error) {
	p, err := generatePassphrase()
	return p, "", err
}
