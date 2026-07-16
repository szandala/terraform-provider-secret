# terraform-provider-secret

An `ansible-vault`-style secrets mechanism for Terraform / OpenTofu.

- Commit **encrypted** values to your repo.
- Decrypt **on-the-fly** during `plan` / `apply`.
- The decrypted value is **ephemeral** — it never lands in state or plan.
- Each secret picks **which env var holds its key**, so you can mix keys
  (per-env, per-team) in one config.

Works on Terraform >= 1.10 or OpenTofu >= 1.7 (ephemeral resources required).

## How it works

`ephemeral "secret"` decrypts an `AES-256-GCM` value whose key is derived with
`scrypt` from a passphrase held in an environment variable. The variable's **name**
is given per-secret by `secret_key` (default `SECRET_KEY`). Because it's an
**ephemeral resource**, Terraform core guarantees the result is never serialized to
state or the plan file — you don't fork core, you lean on the ephemeral value
lifecycle already in core.

## Wire format

```
SECRET1;<base64( salt[16] || nonce[12] || ciphertext+GCMtag )>
```

## Encrypt values

```sh
go build -o secret-encrypt ./cmd/secret-encrypt

export SECRET_KEY='dev passphrase'
./secret-encrypt -value 'p@ssw0rd'
# -> SECRET1;U2FsdGVk...

# a secret encrypted with a different key:
export PROD_SECRET_KEY='prod passphrase'
./secret-encrypt -secret-key PROD_SECRET_KEY -value 'prod-p@ssw0rd'
```

## Use it

```hcl
terraform {
  required_providers {
    secret = { source = "yourname/secret" }
  }
}

# Uses the default SECRET_KEY env var:
ephemeral "secret" "db_password" {
  ciphertext = "SECRET1;U2FsdGVk..."
}

# Uses a different key — good for per-environment secrets:
ephemeral "secret" "prod_db_password" {
  ciphertext  = "SECRET1;Zm9vYmFy..."
  secret_key  = "PROD_SECRET_KEY"
  description = "Production Postgres password for the billing service"
}

provider "postgresql" {
  password = ephemeral.secret.db_password.plaintext
}

resource "some_db" "x" {
  password_wo         = ephemeral.secret.prod_db_password.plaintext
  password_wo_version = 1
}
```

Then:

```sh
export SECRET_KEY='dev passphrase'
export PROD_SECRET_KEY='prod passphrase'
terraform plan
```

If a referenced env var is unset, plan fails with a clear error naming that
variable, instead of leaking anything.

## Constraints (inherent to ephemeral values)

You can reference `.plaintext` only where Terraform accepts ephemeral input:
provider configuration, other ephemeral resources/locals, and write-only (`*_wo`)
resource arguments. You cannot feed it into an ordinary attribute that gets stored
in state — which is exactly the property you wanted.
