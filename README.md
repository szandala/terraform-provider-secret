# terraform-provider-secret

An `ansible-vault`-style secrets mechanism for Terraform / OpenTofu.

- Commit **encrypted** values to your repo.
- Decrypt **on-the-fly** during `plan` / `apply`.
- The decrypted value is **ephemeral** - it never lands in state or plan.
- Each secret picks **which env var holds its key**, so you can mix keys
  (per-env, per-team) in one config.

Requirements:

| Feature                                   | Terraform | OpenTofu |
| ----------------------------------------- | --------- | -------- |
| `ephemeral "secret_secret"`               | >= 1.10   | >= 1.11  |
| `provider::secret::wo_version()`          | >= 1.8    | >= 1.7   |
| write-only `*_wo` sinks (e.g. GSM)        | >= 1.11   | >= 1.11  |

So in practice: **Terraform >= 1.11 or OpenTofu >= 1.11**.

> **0.x note:** the ephemeral resource was renamed from `secret` to
> `secret_secret`. Ephemeral resources have no state, so migrating is just a
> rename in your `.tf` files - see [CHANGELOG.md](CHANGELOG.md).

## How it works

`ephemeral "secret_secret"` decrypts an `AES-256-GCM` value whose key is derived with
`scrypt` from a passphrase held in an environment variable. The variable's **name**
is chosen by `secret_key` on the secret, else `secret_key` on the provider block,
else `SECRET_KEY`. Because it's an
**ephemeral resource**, Terraform core guarantees the result is never serialized to
state or the plan file - you don't fork core, you lean on the ephemeral value
lifecycle already in core.

## Wire format

```
SECRET1;<base64( salt[16] || nonce[12] || ciphertext+GCMtag )>
```

Whitespace anywhere in the value is ignored, so it can be wrapped across lines
(`-wrap 76`), indented in a heredoc, or loaded with `file()`.

## Encrypt values

```sh
go install github.com/szandala/terraform-provider-secret/cmd/secret-encrypt@latest
# or: go build -o secret-encrypt ./cmd/secret-encrypt

export SECRET_KEY='dev passphrase'

# one value (ansible-vault encrypt_string). Prefer stdin: -value ends up in
# your shell history and in `ps`.
printf '%s' 'p@ssw0rd' | secret-encrypt
# -> SECRET1;U2FsdGVk...

# a whole file (ansible-vault encrypt), wrapped for readable diffs
secret-encrypt -in prod.env -out secrets/prod.env.enc -wrap 76

# look at it again / decrypt (ansible-vault view / decrypt)
secret-encrypt -d -in secrets/prod.env.enc
secret-encrypt -d -in secrets/prod.env.enc -out prod.env   # written 0600

# a secret encrypted with a different key:
export PROD_SECRET_KEY='prod passphrase'
secret-encrypt -secret-key PROD_SECRET_KEY -in prod.env -out secrets/prod.env.enc
```

Notes: `-in FILE` is byte-exact; stdin has exactly one trailing newline removed.
Plaintext must be UTF-8 (base64-encode binary first). Keep the decrypted files
out of git (`*.env` in `.gitignore`, commit only `*.env.enc`).

## Use it

```hcl
terraform {
  required_providers {
    secret = { source = "szandala/secret" }
  }
}

# Optional: default env var for every secret below (else SECRET_KEY).
provider "secret" {
  secret_key = "PROD_SECRET_KEY"
}

ephemeral "secret_secret" "db_password" {
  ciphertext = "SECRET1;U2FsdGVk..."
}

# A secret can still pick its own key:
ephemeral "secret_secret" "billing_api_key" {
  ciphertext  = "SECRET1;Zm9vYmFy..."
  secret_key  = "BILLING_SECRET_KEY"
  description = "Billing service API key"
}

provider "postgresql" {
  password = ephemeral.secret_secret.db_password.plaintext
}
```

Then:

```sh
export PROD_SECRET_KEY='prod passphrase'
export BILLING_SECRET_KEY='billing passphrase'
terraform plan    # and apply: the variables are needed in both
```

If a referenced env var is unset, plan fails with a clear error naming that
variable, instead of leaking anything. `secret_key` must be a variable **name**;
if it isn't (e.g. someone pasted the passphrase there), `terraform validate`
rejects it without printing the value.

## Recipe: Google Secret Manager, one root module per environment

Repo layout:

```
infra/
  envs/
    dev/   main.tf  secrets/django.env.enc   (encrypted with DEV_SECRET_KEY)
    qa/    main.tf  secrets/django.env.enc   (encrypted with QA_SECRET_KEY)
    prod/  main.tf  secrets/django.env.enc   (encrypted with PROD_SECRET_KEY)
```

### A) Whole `.env` file -> one GSM secret

Matches the "one `.env` secret per environment" pattern (e.g. `django-environ`
reading `django-settings` at startup):

```hcl
provider "secret" {
  secret_key = "PROD_SECRET_KEY"
}

locals {
  django_env_ct = file("${path.module}/secrets/django.env.enc")
}

ephemeral "secret_secret" "django_env" {
  ciphertext = local.django_env_ct
}

resource "google_secret_manager_secret" "django_env" {
  secret_id = "django-settings"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "django_env" {
  secret                 = google_secret_manager_secret.django_env.id
  secret_data_wo         = ephemeral.secret_secret.django_env.plaintext
  secret_data_wo_version = provider::secret::wo_version(local.django_env_ct)
}
```

Rotate a value: `secret-encrypt -d` the file, edit, encrypt it again, commit,
`apply`. The new ciphertext gives a new `wo_version`, so a new GSM version is
written - no counter to bump by hand.

### B) Many values in one vars file -> one GSM secret each

The `ansible-vault encrypt_string` style: plain YAML with encrypted values,
reviewable key by key.

```yaml
# secrets/prod.yaml
DB_PASSWORD: SECRET1;AAAA...
STRIPE_API_KEY: SECRET1;BBBB...
```

```hcl
locals {
  encrypted = yamldecode(file("${path.module}/secrets/prod.yaml"))
}

ephemeral "secret_secret" "app" {
  for_each   = local.encrypted
  ciphertext = each.value
}

resource "google_secret_manager_secret" "app" {
  for_each  = local.encrypted
  secret_id = lower(replace(each.key, "_", "-"))
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "app" {
  for_each               = local.encrypted
  secret                 = google_secret_manager_secret.app[each.key].id
  secret_data_wo         = ephemeral.secret_secret.app[each.key].plaintext
  secret_data_wo_version = provider::secret::wo_version(each.value)
}
```

`for_each` keys come from the (non-secret) YAML keys, so they are allowed;
the values only ever flow through ephemeral/write-only paths.

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
ephemeral value into state _for assertion only_ - proof that decryption works,
while in normal use nothing echoes it and it never lands in state.

## Where you can safely use `.plaintext` (important)

The ephemeral resource guarantees only one thing: the decrypted value itself is
never written to state or plan. It does **not** protect the value once you hand it
to another resource. If you assign `.plaintext` to an ordinary (state-persisted)
attribute, the _target resource_ would write it into state in cleartext - so
Terraform **refuses** it outright with an `Invalid use of ephemeral value` error.
There is no silent leak and no way to force one; you either use an
ephemeral-friendly sink or Terraform stops you.

So the decrypted value can go into exactly three kinds of places:

### 1. Write-only (`*_wo`) resource arguments - the main pattern

Many providers expose a write-only twin of a sensitive field (e.g. `secret_data`
→ `secret_data_wo`). Write-only arguments are sent to the provider's API and then
forgotten - they are **not** stored in state. Each comes with a `*_wo_version`
argument that must change for the value to be re-sent. The ciphertext is not
ephemeral, so `provider::secret::wo_version(<ciphertext>)` can feed it: it
changes exactly when you re-encrypt.

GCP Secret Manager is the textbook case:

```hcl
resource "google_secret_manager_secret" "db" {
  secret_id = "billing-db-password"
  replication { auto {} }
}

locals {
  db_password_ct = "SECRET1;U2FsdGVk..."
}

ephemeral "secret_secret" "db_password" {
  ciphertext = local.db_password_ct
  secret_key = "PROD_SECRET_KEY"
}

resource "google_secret_manager_secret_version" "db" {
  secret                 = google_secret_manager_secret.db.id
  secret_data_wo         = ephemeral.secret_secret.db_password.plaintext
  secret_data_wo_version = provider::secret::wo_version(local.db_password_ct)
}
```

Nothing about the password reaches state here. Check the provider docs
per-attribute - an argument only qualifies if it actually has a `*_wo` form.

### 2. Provider configuration

Provider blocks accept ephemeral values and don't persist them:

```hcl
provider "postgresql" {
  password = ephemeral.secret_secret.db_password.plaintext
}
```

### 3. Other ephemeral resources / ephemeral locals

You can chain an ephemeral value into another ephemeral construct without it ever
becoming durable.

## Where it does NOT help - and why

Some fields are cleartext _by their own nature_, and no encryption-at-rest trick
changes that. The clearest example is a VM startup script
(`metadata_startup_script`, `user_data`, cloud-init):

```hcl
# DON'T: this both violates ephemeral rules AND wouldn't help if it didn't.
resource "google_compute_instance" "vm" {
  metadata_startup_script = "echo ${ephemeral.secret_secret.db_password.plaintext} > /etc/app.env"
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

Don't push the secret _into_ the machine. Store it once via a `*_wo` sink
(Secret Manager, above) and have the VM **pull it at boot** using its own identity
(GCP service account / AWS instance role):

```hcl
resource "google_compute_instance" "vm" {
  # startup script contains NO secret - just a fetch command:
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

## Security notes

- **The passphrase is the whole security.** Use a long random one per environment
  (`openssl rand -base64 32`) and keep it in your CI's secret store / a password
  manager. scrypt slows brute force down; it can't save `prod123`.
- **Rotating the passphrase** = decrypt and re-encrypt every file with the new
  one. The old ciphertexts stay in git history, so if a passphrase leaks, rotate
  the *secrets* themselves, not only the passphrase.
- Each decryption runs scrypt (N=2^15, ~32 MiB, tens of ms) during both plan and
  apply. Hundreds of individual secrets add up - prefer a few files over many
  tiny values.
- The plaintext is held in provider process memory during the run, like with
  any provider.

## Quick reference

| Sink                                     | Safe? | Why                                                                             |
| ---------------------------------------- | ----- | ------------------------------------------------------------------------------- |
| `*_wo` argument (e.g. `secret_data_wo`)  | ✅    | Not persisted to state                                                          |
| Provider config (e.g. DB `password`)     | ✅    | Ephemeral-aware, not persisted                                                  |
| Another ephemeral resource / local       | ✅    | Stays ephemeral                                                                 |
| Ordinary attribute (most fields)         | ❌    | Terraform errors; would otherwise leak to state                                 |
| VM startup script / user-data / metadata | ❌    | Cleartext at the cloud destination anyway - have the VM pull the secret instead |
