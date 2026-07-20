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

## Testing

Unit tests (crypto round-trip, wrong key, tampering, schema) need no Terraform:

```sh
go test -race ./...
```

Acceptance tests spin up real Terraform (>= 1.10, for ephemeral resources) and
assert the value decrypts correctly. They're behind the `acc` build tag:

```sh
TF_ACC=1 go test -tags acc -v ./internal/provider/
```

They use the `echo` provider from `terraform-plugin-testing` to pull the
ephemeral value into state *for assertion only* — proof that decryption works,
while in normal use nothing echoes it and it never lands in state.

## Where you can safely use `.plaintext` (important)

The ephemeral resource guarantees only one thing: the decrypted value itself is
never written to state or plan. It does **not** protect the value once you hand it
to another resource. If you assign `.plaintext` to an ordinary (state-persisted)
attribute, the *target resource* would write it into state in cleartext — so
Terraform **refuses** it outright with an `Invalid use of ephemeral value` error.
There is no silent leak and no way to force one; you either use an
ephemeral-friendly sink or Terraform stops you.

So the decrypted value can go into exactly three kinds of places:

### 1. Write-only (`*_wo`) resource arguments — the main pattern

Many providers expose a write-only twin of a sensitive field (e.g. `secret_data`
→ `secret_data_wo`). Write-only arguments are sent to the provider's API and then
forgotten — they are **not** stored in state. Pair each with its `*_wo_version`
counter; bump the version when you rotate the secret so the provider re-sends it.

GCP Secret Manager is the textbook case:

```hcl
resource "google_secret_manager_secret" "db" {
  secret_id = "billing-db-password"
  replication { auto {} }
}

ephemeral "secret" "db_password" {
  ciphertext = "SECRET1;U2FsdGVk..."
  secret_key = "PROD_SECRET_KEY"
}

resource "google_secret_manager_secret_version" "db" {
  secret                 = google_secret_manager_secret.db.id
  secret_data_wo         = ephemeral.secret.db_password.plaintext
  secret_data_wo_version = 1   # bump to re-write after rotating the ciphertext
}
```

Nothing about the password reaches state here. Check the provider docs
per-attribute — an argument only qualifies if it actually has a `*_wo` form.

### 2. Provider configuration

Provider blocks accept ephemeral values and don't persist them:

```hcl
provider "postgresql" {
  password = ephemeral.secret.db_password.plaintext
}
```

### 3. Other ephemeral resources / ephemeral locals

You can chain an ephemeral value into another ephemeral construct without it ever
becoming durable.

## Where it does NOT help — and why

Some fields are cleartext *by their own nature*, and no encryption-at-rest trick
changes that. The clearest example is a VM startup script
(`metadata_startup_script`, `user_data`, cloud-init):

```hcl
# DON'T: this both violates ephemeral rules AND wouldn't help if it didn't.
resource "google_compute_instance" "vm" {
  metadata_startup_script = "echo ${ephemeral.secret.db_password.plaintext} > /etc/app.env"
}
```

Two separate problems:

1. `metadata_startup_script` is an ordinary attribute → Terraform rejects the
   ephemeral value with an error. There is no `*_wo` variant for it.
2. Even if there were, the startup script is stored **in the VM's metadata by the
   cloud provider**, readable in plaintext from the GCP/AWS console and from inside
   the instance. Hiding it from Terraform state would buy you nothing; the secret
   is exposed at the destination regardless of Terraform.

This is the same boundary `ansible-vault` has: the vault protects the secret
**at rest in your repo and in transit**, but the moment a task writes it into a
config file on the host, it's plaintext there. The tool secures storage and
transport, not a destination that is inherently cleartext.

### The right pattern for VMs

Don't push the secret *into* the machine. Store it once via a `*_wo` sink
(Secret Manager, above) and have the VM **pull it at boot** using its own identity
(GCP service account / AWS instance role):

```hcl
resource "google_compute_instance" "vm" {
  # startup script contains NO secret — just a fetch command:
  metadata_startup_script = <<-EOT
    #!/bin/bash
    gcloud secrets versions access latest \
      --secret="billing-db-password" > /etc/app/db_password
  EOT

  service_account {
    email  = google_service_account.vm.email
    scopes = ["cloud-platform"]
  }
}
```

Now the ciphertext lives in your repo, the plaintext lives only in Secret Manager
(written via a write-only argument), and the VM retrieves it at runtime under its
own IAM identity. Terraform state never sees the cleartext at any step.

## Quick reference

| Sink                                              | Safe?  | Why |
|---------------------------------------------------|--------|-----|
| `*_wo` argument (e.g. `secret_data_wo`)           | ✅     | Not persisted to state |
| Provider config (e.g. DB `password`)              | ✅     | Ephemeral-aware, not persisted |
| Another ephemeral resource / local                | ✅     | Stays ephemeral |
| Ordinary attribute (most fields)                  | ❌     | Terraform errors; would otherwise leak to state |
| VM startup script / user-data / metadata          | ❌     | Cleartext at the cloud destination anyway — have the VM pull the secret instead |
