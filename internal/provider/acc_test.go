//go:build acc

package provider

import (
	"fmt"
	"os"
	"regexp"
	"strings"
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

// The provider under test, served in-process as "secret".
// Functions need Terraform >= 1.8, ephemeral resources >= 1.10.
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
ephemeral "secret_secret" "test" {
  ciphertext = %q
}

provider "echo" {
  data = ephemeral.secret_secret.test.plaintext
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
ephemeral "secret_secret" "prod" {
  ciphertext = %q
  secret_key = "PROD_SECRET_KEY"
}

provider "echo" {
  data = ephemeral.secret_secret.prod.plaintext
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
ephemeral "secret_secret" "test" {
  ciphertext = %q
}

provider "echo" {
  data = ephemeral.secret_secret.test.plaintext
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
ephemeral "secret_secret" "test" {
  ciphertext = %q
}

provider "echo" {
  data = ephemeral.secret_secret.test.plaintext
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

// The provider-level secret_key is used when a secret does not set its own.
func TestAcc_ProviderDefaultKeyVar(t *testing.T) {
	const pass = "team passphrase"
	const secret = "team-value"

	t.Setenv("TEAM_SECRET_KEY", pass)
	os.Unsetenv("SECRET_KEY")
	ct := mustEncrypt(t, pass, secret)

	config := fmt.Sprintf(`
provider "secret" {
  secret_key = "TEAM_SECRET_KEY"
}

ephemeral "secret_secret" "test" {
  ciphertext = %q
}

provider "echo" {
  data = ephemeral.secret_secret.test.plaintext
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

// A whole .env file, encrypted and wrapped like secret-encrypt -wrap writes it,
// pasted into an indented heredoc, decrypts byte-for-byte.
func TestAcc_DecryptsWrappedMultilineFile(t *testing.T) {
	const pass = "file passphrase"
	const dotenv = "SECRET_KEY=abc\nDB_PASSWORD=p@ss=word\nSTRIPE_API_KEY=sk_test_123\n"

	t.Setenv("SECRET_KEY", pass)
	wrapped := WrapCiphertext(mustEncrypt(t, pass, dotenv), 40)

	config := fmt.Sprintf(`
ephemeral "secret_secret" "env" {
  ciphertext = <<-EOT
    %s
  EOT
}

provider "echo" {
  data = ephemeral.secret_secret.env.plaintext
}

resource "echo" "test" {}
`, strings.ReplaceAll(wrapped, "\n", "\n    "))

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
						knownvalue.StringExact(dotenv)),
				},
			},
		},
	})
}

// Putting the passphrase itself into secret_key is rejected at validate time.
func TestAcc_SecretKeyMustBeAName(t *testing.T) {
	ct := mustEncrypt(t, "whatever", "value")

	config := fmt.Sprintf(`
ephemeral "secret_secret" "test" {
  ciphertext = %q
  secret_key = "this is my passphrase"
}

provider "echo" {
  data = ephemeral.secret_secret.test.plaintext
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
				ExpectError: regexp.MustCompile(`Invalid environment variable name`),
			},
		},
	})
}

// provider::secret::wo_version is deterministic and needs no key.
func TestAcc_WriteOnlyVersionFunction(t *testing.T) {
	ct := mustEncrypt(t, "whatever", "value")

	config := fmt.Sprintf(`
output "v" {
  value = provider::secret::wo_version(%q)
}
`, ct)

	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		ProtoV6ProviderFactories: protoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownOutputValue("v", knownvalue.Int64Exact(WriteOnlyVersion(ct))),
				},
			},
		},
	})
}
