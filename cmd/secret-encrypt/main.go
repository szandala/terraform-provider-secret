// secret-encrypt: turn a plaintext into a SECRET1;... value you can commit.
//
// The passphrase is read from an environment variable whose name you pass with
// -secret-key (default "SECRET_KEY"), matching the ephemeral resource's
// secret_key attribute at runtime.
//
// Usage:
//   export SECRET_KEY='my passphrase'
//   echo -n 'super secret' | secret-encrypt
//   secret-encrypt -value 'super secret'
//
//   export PROD_SECRET_KEY='prod passphrase'
//   secret-encrypt -secret-key PROD_SECRET_KEY -value 'prod secret'
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/szandala/terraform-provider-secret/internal/provider"
)

func main() {
	secretKey := flag.String("secret-key", "SECRET_KEY", "name of the env var holding the passphrase")
	value := flag.String("value", "", "value to encrypt (if unset, read from stdin)")
	flag.Parse()

	passphrase, ok := os.LookupEnv(*secretKey)
	if !ok || passphrase == "" {
		fmt.Fprintf(os.Stderr, "error: env var %q not set\n", *secretKey)
		os.Exit(1)
	}

	plaintext := *value
	if plaintext == "" {
		b, err := io.ReadAll(bufio.NewReader(os.Stdin))
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading stdin: %v\n", err)
			os.Exit(1)
		}
		plaintext = strings.TrimRight(string(b), "\n")
	}

	wire, err := provider.Encrypt(passphrase, plaintext)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encrypt failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(wire)
}
