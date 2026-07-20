package provider

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	cases := []struct {
		name       string
		passphrase string
		plaintext  string
	}{
		{"simple", "correct horse battery staple", "p@ssw0rd"},
		{"empty plaintext", "key", ""},
		{"unicode", "hasło", "zażółć gęślą jaźń 🔐"},
		{"long", strings.Repeat("k", 128), strings.Repeat("secret-", 1000)},
		{"whitespace", "key with spaces", "  leading and trailing  "},
		{"newlines", "key", "line1\nline2\nline3"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := Encrypt(tc.passphrase, tc.plaintext)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}
			if !strings.HasPrefix(wire, magicPrefix) {
				t.Fatalf("wire output missing %q prefix: %q", magicPrefix, wire)
			}

			got, err := Decrypt(tc.passphrase, wire)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}
			if got != tc.plaintext {
				t.Fatalf("round-trip mismatch: got %q, want %q", got, tc.plaintext)
			}
		})
	}
}

func TestDecrypt_WrongPassphrase(t *testing.T) {
	wire, err := Encrypt("right key", "secret value")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = Decrypt("wrong key", wire)
	if err == nil {
		t.Fatal("expected error decrypting with wrong passphrase, got nil")
	}
	// Must not leak whether it was key vs corruption in a distinguishable way.
	if !strings.Contains(err.Error(), "decryption failed") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestDecrypt_EmptyPassphrase(t *testing.T) {
	wire, err := Encrypt("some key", "value")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if _, err := Decrypt("", wire); err == nil {
		t.Fatal("expected error with empty passphrase, got nil")
	}
}

func TestEncrypt_EmptyPassphrase(t *testing.T) {
	if _, err := Encrypt("", "value"); err == nil {
		t.Fatal("expected error encrypting with empty passphrase, got nil")
	}
}

func TestDecrypt_MissingPrefix(t *testing.T) {
	// Valid base64 but no SECRET1; prefix.
	payload := base64.StdEncoding.EncodeToString([]byte("just some bytes here padding padding"))
	if _, err := Decrypt("key", payload); err == nil {
		t.Fatal("expected error for missing prefix, got nil")
	}
}

func TestDecrypt_InvalidBase64(t *testing.T) {
	if _, err := Decrypt("key", magicPrefix+"!!!not base64!!!"); err == nil {
		t.Fatal("expected error for invalid base64, got nil")
	}
}

func TestDecrypt_TooShort(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte("tiny"))
	if _, err := Decrypt("key", magicPrefix+short); err == nil {
		t.Fatal("expected error for too-short payload, got nil")
	}
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	wire, err := Encrypt("key", "important secret")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(wire, magicPrefix))
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	// Flip a bit in the ciphertext body (past salt+nonce). GCM must detect it.
	raw[saltLen+nonceLen] ^= 0x01
	tampered := magicPrefix + base64.StdEncoding.EncodeToString(raw)

	if _, err := Decrypt("key", tampered); err == nil {
		t.Fatal("expected error decrypting tampered ciphertext, got nil")
	}
}

func TestEncrypt_UniqueSaltAndNonce(t *testing.T) {
	// Same input twice must produce different wire values (random salt+nonce),
	// yet both must decrypt back to the same plaintext.
	a, err := Encrypt("key", "same input")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	b, err := Encrypt("key", "same input")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if a == b {
		t.Fatal("two encryptions of the same input produced identical output; salt/nonce not random")
	}

	for _, w := range []string{a, b} {
		got, err := Decrypt("key", w)
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}
		if got != "same input" {
			t.Fatalf("got %q, want %q", got, "same input")
		}
	}
}
