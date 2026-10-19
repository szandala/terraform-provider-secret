# A single value, committed inline:
ephemeral "secret_secret" "db_password" {
  ciphertext  = "SECRET1;U2FsdGVk..."
  secret_key  = "PROD_SECRET_KEY" # name of the env var, NOT the passphrase
  description = "Billing Postgres password"
}

# A whole file (e.g. a Django .env), encrypted with
#   secret-encrypt -secret-key PROD_SECRET_KEY -in prod.env -out secrets/prod.env.enc -wrap 76
ephemeral "secret_secret" "django_env" {
  ciphertext = file("${path.module}/secrets/prod.env.enc")
}
