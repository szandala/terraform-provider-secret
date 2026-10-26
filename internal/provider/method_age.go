package provider

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"filippo.io/age"
)

// AGE1: age (age-encryption.org/v1) with X25519 keys.
//
//	payload = raw (binary, non-armored) age file
//
// Asymmetric: anyone holding the PUBLIC key (age1...) can encrypt a new
// secret, only the holder of the PRIVATE key (AGE-SECRET-KEY-1...) can
// decrypt. The key env var holds:
//   - when encrypting: one or more public keys (whitespace/comma separated).
//     A private key is accepted too; its public half is used.
//   - when decrypting: one or more private keys. Public keys are ignored, and
//     if ONLY public keys are present the error says so explicitly.
//
// Lines starting with '#' are ignored, so the output of
// `secret-encrypt --method age1 --genkey` can be used as is.

func init() { registerMethod(ageMethod{}) }

type ageMethod struct{}

const ageHeader = "age-encryption.org/v1\n"

func (ageMethod) Name() string     { return "age1" }
func (ageMethod) Prefix() string   { return "AGE1;" }
func (ageMethod) Asymmetric() bool { return true }
func (ageMethod) Summary() string {
	return "age X25519. Encrypt with public key(s) age1..., decrypt with private key AGE-SECRET-KEY-1..."
}

func (ageMethod) recipients(key string) ([]age.Recipient, error) {
	var out []age.Recipient
	for i, tok := range keyTokens(key) {
		switch {
		case agePrivateKeyRe.MatchString(tok):
			id, err := age.ParseX25519Identity(tok)
			if err != nil {
				return nil, fmt.Errorf("key #%d: invalid age private key", i+1)
			}
			out = append(out, id.Recipient())
		case agePublicKeyRe.MatchString(tok):
			r, err := age.ParseX25519Recipient(tok)
			if err != nil {
				return nil, fmt.Errorf("key #%d: invalid age public key (bad checksum?)", i+1)
			}
			out = append(out, r)
		default:
			// Not echoed: it might be a passphrase put here by mistake.
			return nil, fmt.Errorf("key #%d is not an age key; expected public key(s) age1... (did you mean --method aes256?)", i+1)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no age public key (age1...) found in the key")
	}
	return out, nil
}

func (ageMethod) identities(key string) ([]age.Identity, error) {
	var out []age.Identity
	sawPublic := false
	for i, tok := range keyTokens(key) {
		switch {
		case agePrivateKeyRe.MatchString(tok):
			id, err := age.ParseX25519Identity(tok)
			if err != nil {
				return nil, fmt.Errorf("key #%d: invalid age private key", i+1)
			}
			out = append(out, id)
		case agePublicKeyRe.MatchString(tok):
			sawPublic = true
		}
	}
	if len(out) == 0 {
		if sawPublic {
			return nil, errors.New("the key is an age PUBLIC key (age1...): it can only encrypt. " +
				"Decryption needs the PRIVATE key (AGE-SECRET-KEY-1...)")
		}
		return nil, errors.New("no age private key (AGE-SECRET-KEY-1...) found in the key")
	}
	return out, nil
}

func (m ageMethod) Seal(key string, plaintext []byte) ([]byte, error) {
	recipients, err := m.recipients(key)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (m ageMethod) Open(key string, payload []byte) ([]byte, error) {
	ids, err := m.identities(key)
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(payload), ids...)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			return nil, errors.New("decryption failed: none of the private keys matches this secret " +
				"(it was encrypted for other public keys)")
		}
		return nil, errors.New("decryption failed: corrupted ciphertext")
	}
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, errors.New("decryption failed: corrupted ciphertext")
	}
	return plaintext, nil
}

func (ageMethod) CheckPayload(payload []byte) error {
	if !bytes.HasPrefix(payload, []byte(ageHeader)) {
		return errors.New("payload is not an age file")
	}
	return nil
}

func (ageMethod) GenerateKey() (string, string, error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return "", "", err
	}
	return id.String(), id.Recipient().String(), nil
}
