package provider

import (
	"encoding/base64"
	"strings"
	"testing"
)

const testPassphrase = "correct horse battery staple"

// methodTestKeys returns (key to encrypt, key to decrypt) for a method.
// Every registered method MUST have a case here; the generic tests below then
// cover it automatically.
func methodTestKeys(t *testing.T, m Method) (string, string) {
	t.Helper()
	switch m.Name() {
	case "aes256", "xchacha20":
		return testPassphrase, testPassphrase
	case "age1":
		secret, public, err := m.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		return public, secret
	default:
		t.Fatalf("method %q has no case in methodTestKeys (crypto_test.go)", m.Name())
		return "", ""
	}
}

func mustEncryptWith(t *testing.T, method, key, plaintext string) string {
	t.Helper()
	wire, err := Encrypt(method, key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt(%s): %v", method, err)
	}
	return wire
}

func TestMethods_Registered(t *testing.T) {
	want := map[string]bool{"aes256": false, "xchacha20": false, "age1": false}
	for _, m := range Methods() {
		if m.Prefix() != strings.ToUpper(m.Name())+";" {
			t.Errorf("%s: prefix %q breaks the ToUpper(name)+\";\" convention", m.Name(), m.Prefix())
		}
		want[m.Name()] = true
	}
	for name, ok := range want {
		if !ok {
			t.Errorf("method %q not registered", name)
		}
	}
	if _, err := LookupMethod(DefaultMethod); err != nil {
		t.Fatalf("default method not registered: %v", err)
	}
	if _, err := LookupMethod("rot13"); err == nil || !strings.Contains(err.Error(), "available") {
		t.Fatalf("unknown method error should list available methods, got %v", err)
	}
}

func TestMethods_RoundTrip(t *testing.T) {
	cases := map[string]string{
		"simple":   "p@ssw0rd",
		"empty":    "",
		"unicode":  "zażółć gęślą jaźń 🔐",
		"newlines": "-----BEGIN CERTIFICATE-----\nMIIB\n\n-----END CERTIFICATE-----\n",
	}
	for _, m := range Methods() {
		enc, dec := methodTestKeys(t, m)
		for name, plaintext := range cases {
			t.Run(m.Name()+"/"+name, func(t *testing.T) {
				wire := mustEncryptWith(t, m.Name(), enc, plaintext)
				if !strings.HasPrefix(wire, m.Prefix()) {
					t.Fatalf("missing %q prefix", m.Prefix())
				}
				if err := ValidateCiphertext(wire); err != nil {
					t.Fatalf("ValidateCiphertext: %v", err)
				}
				got, err := Decrypt(dec, wire)
				if err != nil {
					t.Fatalf("Decrypt: %v", err)
				}
				if got != plaintext {
					t.Fatalf("got %q, want %q", got, plaintext)
				}
			})
		}
	}
}

func TestMethods_WrongKeyFails(t *testing.T) {
	for _, m := range Methods() {
		t.Run(m.Name(), func(t *testing.T) {
			enc, _ := methodTestKeys(t, m)
			_, otherDec := methodTestKeys(t, m)
			if !m.Asymmetric() {
				otherDec = "a different passphrase"
			}
			wire := mustEncryptWith(t, m.Name(), enc, "secret value")
			_, err := Decrypt(otherDec, wire)
			if err == nil || !strings.Contains(err.Error(), "decryption failed") {
				t.Fatalf("expected a decryption failure, got %v", err)
			}
		})
	}
}

func TestMethods_EmptyKey(t *testing.T) {
	for _, m := range Methods() {
		enc, _ := methodTestKeys(t, m)
		wire := mustEncryptWith(t, m.Name(), enc, "value")
		if _, err := Decrypt("", wire); err == nil {
			t.Errorf("%s: decrypt with empty key succeeded", m.Name())
		}
		if _, err := Encrypt(m.Name(), "", "value"); err == nil {
			t.Errorf("%s: encrypt with empty key succeeded", m.Name())
		}
	}
}

func TestMethods_TamperDetected(t *testing.T) {
	for _, m := range Methods() {
		t.Run(m.Name(), func(t *testing.T) {
			enc, dec := methodTestKeys(t, m)
			wire := mustEncryptWith(t, m.Name(), enc, "important secret")
			raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(wire, m.Prefix()))
			if err != nil {
				t.Fatal(err)
			}
			raw[len(raw)-1] ^= 0x01
			tampered := m.Prefix() + base64.StdEncoding.EncodeToString(raw)
			if _, err := Decrypt(dec, tampered); err == nil {
				t.Fatal("tampered ciphertext decrypted successfully")
			}
		})
	}
}

func TestMethods_Truncated(t *testing.T) {
	for _, m := range Methods() {
		enc, _ := methodTestKeys(t, m)
		wire := mustEncryptWith(t, m.Name(), enc, "x")
		short := m.Prefix() + base64.StdEncoding.EncodeToString([]byte("tiny"))
		if err := ValidateCiphertext(short); err == nil {
			t.Errorf("%s: truncated payload accepted", m.Name())
		}
		if err := ValidateCiphertext(wire[:len(m.Prefix())+3]); err == nil {
			t.Errorf("%s: cut-off wire accepted", m.Name())
		}
	}
}

func TestMethods_NonDeterministic(t *testing.T) {
	for _, m := range Methods() {
		enc, _ := methodTestKeys(t, m)
		a := mustEncryptWith(t, m.Name(), enc, "same input")
		b := mustEncryptWith(t, m.Name(), enc, "same input")
		if a == b {
			t.Errorf("%s: two encryptions of the same input are identical", m.Name())
		}
	}
}

func TestMethods_ErrorsNeverContainKey(t *testing.T) {
	const leaky = "my-very-secret-passphrase"
	for _, m := range Methods() {
		enc, _ := methodTestKeys(t, m)
		wire := mustEncryptWith(t, m.Name(), enc, "v")
		if _, err := Decrypt(leaky, wire); err != nil && strings.Contains(err.Error(), leaky) {
			t.Errorf("%s: decrypt error leaks the key: %v", m.Name(), err)
		}
		if _, err := Encrypt(m.Name(), leaky, "v"); err != nil && strings.Contains(err.Error(), leaky) {
			t.Errorf("%s: encrypt error leaks the key: %v", m.Name(), err)
		}
	}
}

func TestLegacySecret1PrefixStillDecrypts(t *testing.T) {
	wire := mustEncryptWith(t, "aes256", testPassphrase, "old value")
	legacy := "SECRET1;" + strings.TrimPrefix(wire, "AES256;")
	got, err := Decrypt(testPassphrase, legacy)
	if err != nil || got != "old value" {
		t.Fatalf("legacy SECRET1 value: got %q, err %v", got, err)
	}
}

func TestAge_PublicKeyCannotDecrypt(t *testing.T) {
	secret, public, err := GenerateKey("age1")
	if err != nil {
		t.Fatal(err)
	}
	wire := mustEncryptWith(t, "age1", public, "value")
	_, err = Decrypt(public, wire)
	if err == nil || !strings.Contains(err.Error(), "PUBLIC key") || !strings.Contains(err.Error(), "AGE-SECRET-KEY-1") {
		t.Fatalf("expected an explicit public-key error, got %v", err)
	}
	if got, err := Decrypt(secret, wire); err != nil || got != "value" {
		t.Fatalf("private key: got %q, err %v", got, err)
	}
}

func TestAge_MultipleRecipients(t *testing.T) {
	s1, p1, _ := GenerateKey("age1")
	s2, p2, _ := GenerateKey("age1")
	wire := mustEncryptWith(t, "age1", p1+", "+p2, "shared")
	for _, s := range []string{s1, s2} {
		if got, err := Decrypt(s, wire); err != nil || got != "shared" {
			t.Fatalf("recipient could not decrypt: %q %v", got, err)
		}
	}
}

func TestAge_GenkeyOutputUsableAsKey(t *testing.T) {
	secret, public, _ := GenerateKey("age1")
	file := "# public key: " + public + "\n" + secret + "\n" // what --genkey prints
	wire := mustEncryptWith(t, "age1", file, "v")            // private key -> its public half
	if got, err := Decrypt(file, wire); err != nil || got != "v" {
		t.Fatalf("got %q, err %v", got, err)
	}
}

func TestAge_PassphraseRejected(t *testing.T) {
	_, err := Encrypt("age1", "just a passphrase", "v")
	if err == nil || !strings.Contains(err.Error(), "not an age key") {
		t.Fatalf("expected 'not an age key', got %v", err)
	}
}

func TestSymmetric_AgeKeyRejected(t *testing.T) {
	secret, public, _ := GenerateKey("age1")
	for _, key := range []string{secret, public} {
		_, err := Encrypt("aes256", key, "v")
		if err == nil || !strings.Contains(err.Error(), "--method age1") {
			t.Fatalf("expected a hint to use --method age1, got %v", err)
		}
		if strings.Contains(err.Error(), key) {
			t.Fatal("error leaks the key")
		}
	}
}

func TestGenerateKey_Symmetric(t *testing.T) {
	for _, name := range []string{"aes256", "xchacha20"} {
		a, pubA, err := GenerateKey(name)
		b, _, _ := GenerateKey(name)
		if err != nil || len(a) < 40 || pubA != "" || a == b {
			t.Errorf("%s: bad generated passphrase (len %d, public %q, err %v)", name, len(a), pubA, err)
		}
	}
}

func TestDecrypt_IgnoresWhitespaceAndWrapping(t *testing.T) {
	wire := mustEncryptWith(t, "aes256", testPassphrase, "KEY1=a\nKEY2=b\n")
	variants := map[string]string{
		"trailing newline (file())": wire + "\n",
		"crlf":                      wire + "\r\n",
		"wrapped at 20":             WrapCiphertext(wire, 20),
		"indented heredoc":          "  " + strings.ReplaceAll(WrapCiphertext(wire, 30), "\n", "\n  ") + "\n",
	}
	for name, v := range variants {
		t.Run(name, func(t *testing.T) {
			got, err := Decrypt(testPassphrase, v)
			if err != nil || got != "KEY1=a\nKEY2=b\n" {
				t.Fatalf("got %q, err %v", got, err)
			}
		})
	}
}

func TestWrapCiphertext(t *testing.T) {
	wire := mustEncryptWith(t, "aes256", testPassphrase, strings.Repeat("x", 200))
	wrapped := WrapCiphertext(wire, 64)
	for i, line := range strings.Split(wrapped, "\n") {
		if len(line) > 64 {
			t.Fatalf("line %d is %d chars, want <= 64", i, len(line))
		}
	}
	if NormalizeCiphertext(wrapped) != wire {
		t.Fatal("unwrapping did not restore the original wire string")
	}
	if WrapCiphertext(wire, 0) != wire {
		t.Fatal("width 0 must not wrap")
	}
}

func TestEncrypt_RejectsInvalidUTF8(t *testing.T) {
	if _, err := Encrypt("aes256", "key", string([]byte{0xff, 0xfe, 0x00})); err == nil {
		t.Fatal("expected error for non-UTF-8 plaintext, got nil")
	}
}

func TestValidateCiphertext_Malformed(t *testing.T) {
	for _, bad := range []string{"", "p@ssw0rd", "AES256;", "AES256;!!!", "ROT13;YWJj", "no-prefix-at-all"} {
		if err := ValidateCiphertext(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	err := ValidateCiphertext("SUPERLONGUNKNOWNPREFIX-THAT-COULD-BE-A-PASSWORD;abc")
	if err == nil || strings.Contains(err.Error(), "COULD-BE-A-PASSWORD") {
		t.Fatalf("unknown prefix error should truncate the prefix, got %v", err)
	}
}

func TestWriteOnlyVersion(t *testing.T) {
	a := mustEncryptWith(t, "aes256", testPassphrase, "same")
	b := mustEncryptWith(t, "aes256", testPassphrase, "same")

	va := WriteOnlyVersion(a)
	if va <= 0 || va >= 1<<53 {
		t.Fatalf("version %d out of range (0, 2^53)", va)
	}
	if WriteOnlyVersion(a) != va {
		t.Fatal("version is not deterministic")
	}
	if WriteOnlyVersion(WrapCiphertext(a, 10)+"\n") != va {
		t.Fatal("version must ignore whitespace / wrapping")
	}
	if WriteOnlyVersion(b) == va {
		t.Fatal("re-encrypting must change the version")
	}
}
