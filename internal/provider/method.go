package provider

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Wire format of every encrypted value:
//
//	<PREFIX>;<base64(payload)>
//
// The prefix names the method that produced the payload (AES256, XCHACHA20,
// AGE1, ...), so one repository can mix methods and Decrypt picks the right
// one by itself. Whitespace anywhere in the wire string is ignored, so a value
// can be wrapped across lines, indented in a heredoc, or loaded with file().
//
// To add a method, copy method_template_symmetric.go or
// method_template_asymmetric.go (see the comments inside them).

// Method is one encryption scheme.
//
// "key" is always the content of the key environment variable (SECRET_KEY by
// default): a passphrase for symmetric methods; public key(s) to encrypt and
// a private key to decrypt for asymmetric ones.
//
// Implementations must never put key material into error messages: they end
// up in Terraform output and CI logs.
type Method interface {
	// Name is the CLI --method value, lowercase, e.g. "aes256".
	Name() string
	// Prefix is the wire prefix including ';'. By convention
	// strings.ToUpper(Name()) + ";", e.g. "AES256;".
	Prefix() string
	// Asymmetric is true when encryption uses a public key that cannot decrypt.
	Asymmetric() bool
	// Summary is a one-line description for help texts.
	Summary() string
	// Seal encrypts plaintext. The returned payload is base64-encoded by the caller.
	Seal(key string, plaintext []byte) ([]byte, error)
	// Open decrypts a payload produced by Seal.
	Open(key string, payload []byte) ([]byte, error)
	// CheckPayload validates the payload structure without any key, so that
	// `terraform validate` catches truncated values.
	CheckPayload(payload []byte) error
	// GenerateKey returns a new random key. secret goes into the key env var;
	// public is the shareable encryption key ("" for symmetric methods).
	GenerateKey() (secret, public string, err error)
}

// DefaultMethod is used by the CLI when --method is not given.
const DefaultMethod = "aes256"

var (
	methodsByName   = map[string]Method{}
	methodsByPrefix = map[string]Method{}
)

// registerMethod is called from the init() of each method_*.go file.
// legacyPrefixes are extra prefixes the method can still DECRYPT (old names).
func registerMethod(m Method, legacyPrefixes ...string) {
	if m.Name() != strings.ToLower(m.Name()) || !strings.HasSuffix(m.Prefix(), ";") {
		panic(fmt.Sprintf("method %q: name must be lowercase and prefix must end with ';'", m.Name()))
	}
	if _, dup := methodsByName[m.Name()]; dup {
		panic(fmt.Sprintf("method %q registered twice", m.Name()))
	}
	methodsByName[m.Name()] = m
	for _, p := range append([]string{m.Prefix()}, legacyPrefixes...) {
		if _, dup := methodsByPrefix[p]; dup {
			panic(fmt.Sprintf("prefix %q registered twice", p))
		}
		methodsByPrefix[p] = m
	}
}

// Methods returns all registered methods sorted by name.
func Methods() []Method {
	out := make([]Method, 0, len(methodsByName))
	for _, m := range methodsByName {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// LookupMethod finds a method by its CLI name.
func LookupMethod(name string) (Method, error) {
	if m, ok := methodsByName[strings.ToLower(strings.TrimSpace(name))]; ok {
		return m, nil
	}
	names := make([]string, 0, len(methodsByName))
	for _, m := range Methods() {
		names = append(names, m.Name())
	}
	return nil, fmt.Errorf("unknown method %q (available: %s)", name, strings.Join(names, ", "))
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

// parseWire finds the method by prefix and decodes the payload. No key needed.
func parseWire(wire string) (Method, []byte, error) {
	wire = NormalizeCiphertext(wire)
	head, body, ok := strings.Cut(wire, ";")
	if !ok {
		return nil, nil, errors.New(`ciphertext has no "<METHOD>;" prefix (e.g. "AES256;...")`)
	}
	m, ok := methodsByPrefix[head+";"]
	if !ok {
		// Only the part before ';' is shown, never the payload.
		if len(head) > 16 {
			head = head[:16] + "..."
		}
		return nil, nil, fmt.Errorf("unknown ciphertext prefix %q", head+";")
	}
	payload, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid base64 payload: %w", err)
	}
	if err := m.CheckPayload(payload); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", m.Name(), err)
	}
	return m, payload, nil
}

// ValidateCiphertext reports whether wire is structurally valid (no decryption).
func ValidateCiphertext(wire string) error {
	_, _, err := parseWire(wire)
	return err
}

// MethodOf returns the method a ciphertext was produced with.
func MethodOf(wire string) (Method, error) {
	m, _, err := parseWire(wire)
	return m, err
}

// Encrypt turns plaintext into a "<PREFIX>;..." wire string.
func Encrypt(method, key, plaintext string) (string, error) {
	m, err := LookupMethod(method)
	if err != nil {
		return "", err
	}
	if key == "" {
		return "", errors.New("empty key")
	}
	if !utf8.ValidString(plaintext) {
		// Terraform strings must be UTF-8; such a value could never be decrypted
		// into an attribute, so refuse early instead of at plan time.
		return "", errors.New("plaintext is not valid UTF-8; base64-encode binary data before encrypting")
	}
	payload, err := m.Seal(key, []byte(plaintext))
	if err != nil {
		return "", err
	}
	return m.Prefix() + base64.StdEncoding.EncodeToString(payload), nil
}

// Decrypt reverses Encrypt; the method is detected from the prefix.
func Decrypt(key, wire string) (string, error) {
	m, payload, err := parseWire(wire)
	if err != nil {
		return "", err
	}
	if key == "" {
		return "", errors.New("empty key")
	}
	plaintext, err := m.Open(key, payload)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(plaintext) {
		return "", errors.New("decrypted value is not valid UTF-8; Terraform strings must be UTF-8 (base64-encode binary data before encrypting)")
	}
	return string(plaintext), nil
}

// GenerateKey creates a new random key for the given method.
func GenerateKey(method string) (secret, public string, err error) {
	m, err := LookupMethod(method)
	if err != nil {
		return "", "", err
	}
	return m.GenerateKey()
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
