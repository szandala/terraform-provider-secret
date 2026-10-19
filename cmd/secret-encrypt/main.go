// secret-encrypt: turn a plaintext into a SECRET1;... value you can commit,
// or (with -d) turn it back - the ansible-vault encrypt / view workflow.
//
// The passphrase is read from an environment variable whose name you pass with
// -secret-key (default "SECRET_KEY"), matching the secret_secret ephemeral
// resource's secret_key attribute at runtime.
//
// Usage:
//
//	export SECRET_KEY='my passphrase'
//	printf '%s' 'super secret' | secret-encrypt          # one value, from stdin
//	secret-encrypt -in prod.env -out prod.env.enc -wrap 76 # whole file
//	secret-encrypt -d -in prod.env.enc                     # view it again
//
//	export PROD_SECRET_KEY='prod passphrase'
//	secret-encrypt -secret-key PROD_SECRET_KEY -in prod.env -out prod.env.enc
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/szandala/terraform-provider-secret/internal/provider"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	secretKey := flag.String("secret-key", "SECRET_KEY", "name of the env var holding the passphrase")
	value := flag.String("value", "", "value to encrypt (visible in shell history and `ps`; prefer stdin or -in)")
	in := flag.String("in", "", "read input from this file instead of stdin; file contents are used byte-for-byte")
	out := flag.String("out", "", "write output to this file instead of stdout (may be the same as -in)")
	wrap := flag.Int("wrap", 0, "wrap ciphertext at N columns, e.g. 76 for files committed to git (0 = one line)")
	decrypt := flag.Bool("d", false, "decrypt instead of encrypt")
	flag.Parse()

	if flag.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flag.Args(), " "))
	}
	valueSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "value" {
			valueSet = true
		}
	})
	if valueSet && *in != "" {
		return fmt.Errorf("use either -value or -in, not both")
	}
	if valueSet && *decrypt {
		return fmt.Errorf("-value cannot be used with -d; pass the ciphertext via stdin or -in")
	}

	passphrase, ok := os.LookupEnv(*secretKey)
	if !ok || passphrase == "" {
		return fmt.Errorf("env var %q not set or empty", *secretKey)
	}

	var input string
	switch {
	case valueSet:
		input = *value
	case *in != "" && *in != "-":
		b, err := os.ReadFile(*in)
		if err != nil {
			return err
		}
		input = string(b)
	default:
		if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
			fmt.Fprintln(os.Stderr, "reading from terminal, finish with Ctrl-D (input is echoed; prefer a pipe or -in)")
		}
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("reading stdin: %w", err)
		}
		// Drop exactly ONE trailing newline (from `echo` or a terminal); keep
		// anything else. Use -in for byte-exact input.
		input = string(b)
		if strings.HasSuffix(input, "\r\n") {
			input = input[:len(input)-2]
		} else {
			input = strings.TrimSuffix(input, "\n")
		}
	}

	if *decrypt {
		plaintext, err := provider.Decrypt(passphrase, input)
		if err != nil {
			return err
		}
		return emit(*out, plaintext, 0o600)
	}

	wire, err := provider.Encrypt(passphrase, input)
	if err != nil {
		return err
	}
	return emit(*out, provider.WrapCiphertext(wire, *wrap)+"\n", 0o644)
}

func emit(path, content string, perm os.FileMode) error {
	if path == "" || path == "-" {
		_, err := io.WriteString(os.Stdout, content)
		return err
	}
	return os.WriteFile(path, []byte(content), perm)
}
