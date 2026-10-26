# Changelog

## Unreleased

### Added

- Pluggable encryption methods, chosen with `secret-encrypt --method` and
  detected from the ciphertext prefix when decrypting:
  - `aes256` (`AES256;`): AES-256-GCM + scrypt. Default.
  - `xchacha20` (`XCHACHA20;`): XChaCha20-Poly1305 + Argon2id (64 MiB).
  - `age1` (`AGE1;`): asymmetric age X25519. Encrypt with public key(s),
    decrypt with the private key. Decrypting with a public key gives an
    explicit error instead of a generic failure.
- Templates for new methods: `internal/provider/method_template_symmetric.go`
  and `method_template_asymmetric.go`; generic tests cover every registered
  method.
- `secret-encrypt --genkey` (random passphrase, or age key pair) and
  `--version`.
- Release assets: `secret-encrypt_<version>_<os>_<arch>` archives for
  linux/darwin/windows (amd64, arm64) plus `secret-encrypt_<version>_SHA256SUMS`.
  The provider's own SHA256SUMS is unchanged.

### Changed

- The default prefix is now `AES256;` instead of `SECRET1;`. Same algorithm;
  existing `SECRET1;` values keep decrypting, nothing needs re-encrypting.
- Symmetric methods refuse an age key in the key variable with a hint to use
  `--method age1`.
- New dependency: `filippo.io/age`.
- `.gitignore`: binaries are ignored only in the repo root (the old pattern
  also matched the `cmd/secret-encrypt/` directory).

## 0.x - rename to secret_secret

### BREAKING

- The ephemeral resource is renamed from `secret` to `secret_secret`, following
  the `<provider>_<name>` convention. Ephemeral resources have no state, so the
  migration is a plain rename in configuration:
  - `ephemeral "secret" "x"` -> `ephemeral "secret_secret" "x"`
  - `ephemeral.secret.x.plaintext` -> `ephemeral.secret_secret.x.plaintext`

### Added

- Provider-level `secret_key`: default env var name for every secret that doesn't
  set its own (resource > provider > `SECRET_KEY`).
- `provider::secret::wo_version(ciphertext)`: derives a `*_wo_version` number from
  the ciphertext, so re-encrypting a secret automatically re-sends it.
- `secret-encrypt`: `-in` / `-out` (whole files, like `ansible-vault encrypt`),
  `-d` (decrypt / view), `-wrap N` (line-wrapped output for git diffs).
- `terraform validate` now checks the ciphertext format (no key needed) and that
  `secret_key` looks like a variable name.

### Changed

- Whitespace inside `ciphertext` is ignored: wrapped values, indented heredocs and
  `file()` with a trailing newline all work.
- Decryption errors name the env var that was used.
- Non-UTF-8 plaintexts are rejected (Terraform strings must be UTF-8).
- `secret-encrypt` reading stdin strips exactly one trailing newline instead of
  all of them; `-in FILE` is byte-exact. `-value ""` now encrypts an empty string
  instead of waiting on stdin.

### Fixed

- `secret_key` set to something that isn't a variable name (typically the
  passphrase itself) used to be echoed back in the "not set" error, i.e. into
  CI logs. It is now rejected without being printed.
- Docs: OpenTofu supports ephemeral resources from 1.11 (not 1.7); write-only
  `*_wo` arguments need Terraform >= 1.11.
