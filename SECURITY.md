# Security policy

## Supported versions

Security fixes are released for the latest `1.x` version only.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report them privately through GitHub:
<https://github.com/szandala/terraform-provider-secret/security/advisories/new>
("Report a vulnerability" on the repository's Security tab).

Include, if you can:

- the affected version (`secret-encrypt --version`, or the provider version),
- what you expected and what happened, with a minimal reproduction,
- the impact you see (e.g. plaintext or key ends up in state, plan, logs or
  error messages; ciphertext can be forged or decrypted without the key).

Never include real keys or secrets in a report.

You can expect an acknowledgement within a few days. Fixes are developed
privately and released together with an advisory crediting the reporter, unless
you prefer to stay anonymous.

## Scope

In scope:

- the `secret_secret` ephemeral resource and the `wo_version` function,
- the `secret-encrypt` CLI,
- the wire format and the AES256 / XCHACHA20 / AGE1 implementations.

Out of scope (see "Security notes" and "Where you can safely use `.plaintext`"
in the README):

- weak passphrases: the key is the whole security,
- secrets that Terraform or a provider writes in clear text at the destination
  (VM user data, startup scripts, ...),
- vulnerabilities in Terraform, OpenTofu or other providers.

## Design guarantees worth reporting if broken

- Decrypted values never reach state or plan.
- Error messages and diagnostics never contain key material or plaintext.
- A wrong key and a tampered ciphertext are not distinguishable for the
  symmetric methods.
