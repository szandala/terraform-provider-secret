//go:build ignore

// TEMPLATE for a new ASYMMETRIC (public/private key) method. Not compiled.
//
// 1. Copy to method_<name>.go, remove the //go:build line.
// 2. Replace "examplepk" / "EXAMPLEPK" with your method name.
// 3. Key env var contract (same as age1):
//      encrypt: one or more PUBLIC keys, whitespace/comma separated
//      decrypt: one or more PRIVATE keys
//    Use keyTokens(key) to split it ('#' lines are skipped). If decryption
//    gets only public keys, say so explicitly - users WILL try that.
// 4. Errors must never contain key material (private keys, or a passphrase
//    someone put in the variable by mistake). Refer to keys by position.
// 5. Add a case to methodTestKeys in crypto_test.go, update README/CHANGELOG.

package provider

import (
	"errors"
	"fmt"
	"strings"
)

func init() { registerMethod(examplepkMethod{}) }

type examplepkMethod struct{}

const (
	examplepkPublicPrefix  = "pub1"
	examplepkPrivatePrefix = "PRIV-1"
)

func (examplepkMethod) Name() string     { return "examplepk" }
func (examplepkMethod) Prefix() string   { return "EXAMPLEPK;" }
func (examplepkMethod) Asymmetric() bool { return true }
func (examplepkMethod) Summary() string {
	return "Scheme X. Encrypt with public key(s) pub1..., decrypt with private key PRIV-1..."
}

func (examplepkMethod) Seal(key string, plaintext []byte) ([]byte, error) {
	var publicKeys []string
	for i, tok := range keyTokens(key) {
		if !strings.HasPrefix(tok, examplepkPublicPrefix) {
			return nil, fmt.Errorf("key #%d is not a public key (pub1...)", i+1)
		}
		publicKeys = append(publicKeys, tok)
	}
	if len(publicKeys) == 0 {
		return nil, errors.New("no public key found in the key")
	}
	// Usually: random file key, encrypt plaintext with an AEAD under it, and
	// wrap the file key for every public key (hybrid encryption). The payload
	// must contain everything Open needs except the private key.
	return nil, errors.New("not implemented")
}

func (examplepkMethod) Open(key string, payload []byte) ([]byte, error) {
	var privateKeys []string
	sawPublic := false
	for _, tok := range keyTokens(key) {
		switch {
		case strings.HasPrefix(tok, examplepkPrivatePrefix):
			privateKeys = append(privateKeys, tok)
		case strings.HasPrefix(tok, examplepkPublicPrefix):
			sawPublic = true
		}
	}
	if len(privateKeys) == 0 {
		if sawPublic {
			return nil, errors.New("the key is a PUBLIC key: it can only encrypt; decryption needs the PRIVATE key")
		}
		return nil, errors.New("no private key found in the key")
	}
	// Try each private key; distinguish "no key matches" from "corrupted"
	// only if the scheme can tell them apart without leaking anything.
	return nil, errors.New("decryption failed: none of the private keys matches this secret")
}

func (examplepkMethod) CheckPayload(payload []byte) error {
	if len(payload) == 0 {
		return errors.New("empty payload")
	}
	return nil
}

func (examplepkMethod) GenerateKey() (secret, public string, err error) {
	// return the private key string and its public key string
	return "", "", errors.New("not implemented")
}
