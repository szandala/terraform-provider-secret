//go:build ignore

// TEMPLATE for a new SYMMETRIC (passphrase) method. Not compiled (build tag above).
//
// 1. Copy to method_<name>.go, remove the //go:build line.
// 2. Replace "example" / "EXAMPLE" with your method name (lowercase name,
//    uppercase prefix), pick a cipher and a KDF, and fill in the sizes.
// 3. Never change the payload layout or KDF parameters of a released method:
//    existing ciphertexts would stop decrypting. Add a new method instead
//    (e.g. "example2"), or keep the old prefix as a legacy prefix:
//    registerMethod(exampleMethod{}, "OLDNAME;").
// 4. Add a case to methodTestKeys in crypto_test.go - the generic tests then
//    cover round trip, wrong key, tampering, truncation and validation.
// 5. Mention it in README.md ("Methods") and CHANGELOG.md.

package provider

import "errors"

func init() { registerMethod(exampleMethod{}) }

type exampleMethod struct{}

const (
	exampleSaltLen  = 16
	exampleNonceLen = 12
	exampleTagLen   = 16
)

func (exampleMethod) Name() string     { return "example" }
func (exampleMethod) Prefix() string   { return "EXAMPLE;" }
func (exampleMethod) Asymmetric() bool { return false }
func (exampleMethod) Summary() string  { return "Cipher X, passphrase via KDF Y (params)." }

func (m exampleMethod) Seal(key string, plaintext []byte) ([]byte, error) {
	if err := checkPassphrase(m, key); err != nil { // rejects age keys
		return nil, err
	}
	salt, err := randomBytes(exampleSaltLen)
	if err != nil {
		return nil, err
	}
	nonce, err := randomBytes(exampleNonceLen)
	if err != nil {
		return nil, err
	}
	// derivedKey := KDF(key, salt)
	// aead := NewAEAD(derivedKey)
	// return aead.Seal(append(salt, nonce...), nonce, plaintext, nil), nil
	_, _ = salt, nonce
	return nil, errors.New("not implemented")
}

func (m exampleMethod) Open(key string, payload []byte) ([]byte, error) {
	if err := checkPassphrase(m, key); err != nil {
		return nil, err
	}
	// CheckPayload already ran, so the slicing below is safe.
	salt := payload[:exampleSaltLen]
	nonce := payload[exampleSaltLen : exampleSaltLen+exampleNonceLen]
	sealed := payload[exampleSaltLen+exampleNonceLen:]
	// derivedKey := KDF(key, salt)
	// plaintext, err := NewAEAD(derivedKey).Open(nil, nonce, sealed, nil)
	// if err != nil {
	// 	return nil, errDecrypt // same error for wrong key and tampering
	// }
	_, _, _ = salt, nonce, sealed
	return nil, errDecrypt
}

func (exampleMethod) CheckPayload(payload []byte) error {
	if len(payload) < exampleSaltLen+exampleNonceLen+exampleTagLen {
		return errors.New("payload too short / corrupt")
	}
	return nil
}

func (exampleMethod) GenerateKey() (string, string, error) {
	p, err := generatePassphrase()
	return p, "", err
}
