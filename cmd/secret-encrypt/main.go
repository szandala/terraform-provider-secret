// secret-encrypt: turn a plaintext into an encrypted value you can commit,
// or (with -d) turn it back - the ansible-vault encrypt / view workflow.
//
// The key is always read from an environment variable, SECRET_KEY by default
// (another name with --secret-key), matching the secret_secret ephemeral
// resource's secret_key attribute:
//
//	aes256, xchacha20 (symmetric): SECRET_KEY = passphrase, for both ways
//	age1 (asymmetric):             SECRET_KEY = public key(s) age1... to encrypt,
//	                               private key AGE-SECRET-KEY-1... to decrypt
//
// Usage:
//
//	export SECRET_KEY='my passphrase'
//	printf '%s' 'super secret' | secret-encrypt                 # aes256
//	secret-encrypt --method xchacha20 --in prod.env --out prod.env.enc --wrap 76
//	secret-encrypt -d --in prod.env.enc                          # method from prefix
//
//	secret-encrypt --method age1 --genkey > prod.age1key          # new key pair
//	export SECRET_KEY=age1...                                    # public key
//	printf '%s' 'super secret' | secret-encrypt --method age1
//	export SECRET_KEY="$(cat prod.age1key)"                       # private key
//	secret-encrypt -d --in prod.env.enc
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/szandala/terraform-provider-secret/internal/provider"
)

// version is set by GoReleaser (-X main.version=...).
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, "Usage: secret-encrypt [flags]\n\n")
	fmt.Fprintf(out, "Encrypts stdin (or --in / --value) to <METHOD>;<base64>, or decrypts with -d.\n")
	fmt.Fprintf(out, "The key is read from the env var named by --secret-key (default SECRET_KEY).\n\n")
	fmt.Fprintf(out, "Methods:\n")
	for _, m := range provider.Methods() {
		kind := "symmetric "
		if m.Asymmetric() {
			kind = "asymmetric"
		}
		def := ""
		if m.Name() == provider.DefaultMethod {
			def = " (default)"
		}
		fmt.Fprintf(out, "  %-10s %s  %s%s\n", m.Name(), kind, m.Summary(), def)
	}
	fmt.Fprintf(out, "\nFlags (one or two dashes):\n")
	flag.PrintDefaults()
}

func run() error {
	method := flag.String("method", provider.DefaultMethod, "encryption method (see list above); ignored with -d, which detects it from the prefix")
	secretKey := flag.String("secret-key", "SECRET_KEY", "name of the env var holding the key")
	value := flag.String("value", "", "value to encrypt (visible in shell history and ps; prefer stdin or --in)")
	in := flag.String("in", "", "read input from this file instead of stdin; file contents are used byte-for-byte")
	out := flag.String("out", "", "write output to this file instead of stdout (may be the same as --in)")
	wrap := flag.Int("wrap", 0, "wrap ciphertext at N columns, e.g. 76 for files committed to git (0 = one line)")
	decrypt := flag.Bool("d", false, "decrypt instead of encrypt")
	genkey := flag.Bool("genkey", false, "print a new random key for --method (age1: private key + public key comment) and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return nil
	}
	if flag.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flag.Args(), " "))
	}
	set := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })

	if *genkey {
		return generate(*method, *out)
	}
	if set["value"] && *in != "" {
		return fmt.Errorf("use either --value or --in, not both")
	}
	if set["value"] && *decrypt {
		return fmt.Errorf("--value cannot be used with -d; pass the ciphertext via stdin or --in")
	}

	key, ok := os.LookupEnv(*secretKey)
	if !ok || key == "" {
		return fmt.Errorf("env var %q not set or empty", *secretKey)
	}

	input, err := readInput(set["value"], *value, *in)
	if err != nil {
		return err
	}

	if *decrypt {
		m, err := provider.MethodOf(input)
		if err != nil {
			return err
		}
		if set["method"] && m.Name() != strings.ToLower(*method) {
			return fmt.Errorf("--method %s given, but the ciphertext is %s", *method, m.Prefix())
		}
		plaintext, err := provider.Decrypt(key, input)
		if err != nil {
			return fmt.Errorf("using the key from %q: %w", *secretKey, err)
		}
		return emit(*out, plaintext, 0o600)
	}

	wire, err := provider.Encrypt(*method, key, input)
	if err != nil {
		return fmt.Errorf("using the key from %q: %w", *secretKey, err)
	}
	return emit(*out, provider.WrapCiphertext(wire, *wrap)+"\n", 0o644)
}

func generate(method, out string) error {
	secret, public, err := provider.GenerateKey(method)
	if err != nil {
		return err
	}
	content := secret + "\n"
	if public != "" {
		// The comment line is ignored when this output is used as SECRET_KEY.
		content = "# public key: " + public + "\n" + content
		fmt.Fprintf(os.Stderr, "Public key (share it, commit it): %s\n", public)
	}
	return emit(out, content, 0o600)
}

func readInput(valueSet bool, value, in string) (string, error) {
	switch {
	case valueSet:
		return value, nil
	case in != "" && in != "-":
		b, err := os.ReadFile(in)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		fmt.Fprintln(os.Stderr, "reading from terminal, finish with Ctrl-D (input is echoed; prefer a pipe or --in)")
	}
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("reading stdin: %w", err)
	}
	// Drop exactly ONE trailing newline (from `echo` or a terminal); keep
	// anything else. Use --in for byte-exact input.
	s := string(b)
	if strings.HasSuffix(s, "\r\n") {
		return s[:len(s)-2], nil
	}
	return strings.TrimSuffix(s, "\n"), nil
}

func emit(path, content string, perm os.FileMode) error {
	if path == "" || path == "-" {
		_, err := io.WriteString(os.Stdout, content)
		return err
	}
	return os.WriteFile(path, []byte(content), perm)
}
