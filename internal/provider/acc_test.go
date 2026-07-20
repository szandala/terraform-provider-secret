//go:build acc

package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/echoprovider"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

// The provider under test, served in-process as "secret"
var protoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"secret": providerserver.NewProtocol6WithError(New("test")()),
}

// The echo provider (from terraform-plugin-testing) lets us pull an ephemeral
// value into state SOLELY for assertions. In real use nothing echoes the value,
// so it never reaches state - that's the whole guarantee. Here we deliberately
// echo it so we can assert the decrypted plaintext is correct.
var echoFactory = map[string]func() (tfprotov6.ProviderServer, error){
	"echo": echoprovider.NewProviderServer(),
}

func mergeFactories(a, b map[string]func() (tfprotov6.ProviderServer, error)) map[string]func() (tfprotov6.ProviderServer, error) {
	out := make(map[string]func() (tfprotov6.ProviderServer, error), len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func mustEncrypt(t *testing.T, passphrase, plaintext string) string {
	t.Helper()
	wire, err := Encrypt(passphrase, plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt test fixture: %v", err)
	}
	return wire
}

// Decrypts with the default SECRET_KEY env var and asserts the plaintext is
// recovered correctly (proving Open() decrypts as expected).
func TestAcc_DecryptsWithDefaultKey(t *testing.T) {
	const pass = "acc test passphrase"
	const secret = "s3cr3t-value"

	t.Setenv("SECRET_KEY", pass)
	ct := mustEncrypt(t, pass, secret)

	config := fmt.Sprintf(`
ephemeral "secret" "test" {
  ciphertext = %q
}

provider "echo" {
  data = ephemeral.secret.test.plaintext
}

resource "echo" "test" {}
`, ct)

	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		ProtoV6ProviderFactories: mergeFactories(protoV6ProviderFactories, echoFactory),
		Steps: []resource.TestStep{
			{
				Config: config,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data"),
						knownvalue.StringExact(secret)),
				},
			},
		},
	})
}

// Decrypts using a custom env var named via secret_key.
func TestAcc_DecryptsWithCustomKeyVar(t *testing.T) {
	const pass = "prod passphrase"
	const secret = "prod-only-value"

	t.Setenv("PROD_SECRET_KEY", pass)
	ct := mustEncrypt(t, pass, secret)

	config := fmt.Sprintf(`
ephemeral "secret" "prod" {
  ciphertext = %q
  secret_key = "PROD_SECRET_KEY"
}

provider "echo" {
  data = ephemeral.secret.prod.plaintext
}

resource "echo" "test" {}
`, ct)

	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		ProtoV6ProviderFactories: mergeFactories(protoV6ProviderFactories, echoFactory),
		Steps: []resource.TestStep{
			{
				Config: config,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data"),
						knownvalue.StringExact(secret)),
				},
			},
		},
	})
}

// A missing env var must fail with a clear, named error.
func TestAcc_MissingEnvVarFails(t *testing.T) {
	os.Unsetenv("SECRET_KEY")
	ct := mustEncrypt(t, "whatever", "value")

	config := fmt.Sprintf(`
ephemeral "secret" "test" {
  ciphertext = %q
}

provider "echo" {
  data = ephemeral.secret.test.plaintext
}

resource "echo" "test" {}
`, ct)

	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		ProtoV6ProviderFactories: mergeFactories(protoV6ProviderFactories, echoFactory),
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`Decryption key not found`),
			},
		},
	})
}

// A wrong key must fail to decrypt (GCM auth failure).
func TestAcc_WrongKeyFails(t *testing.T) {
	t.Setenv("SECRET_KEY", "the wrong key")
	ct := mustEncrypt(t, "the right key", "value")

	config := fmt.Sprintf(`
ephemeral "secret" "test" {
  ciphertext = %q
}

provider "echo" {
  data = ephemeral.secret.test.plaintext
}

resource "echo" "test" {}
`, ct)

	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		ProtoV6ProviderFactories: mergeFactories(protoV6ProviderFactories, echoFactory),
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`Failed to decrypt secret`),
			},
		},
	})
}
