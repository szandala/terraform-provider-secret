# A single value, committed inline:
ephemeral "secret_secret" "db_password" {
  ciphertext  = "AES256;U2FsdGVk..."
  secret_key  = "PROD_SECRET_KEY" # name of the env var, NOT the key itself
  description = "Billing Postgres password"
}

# A whole file (e.g. a Django .env), encrypted with
#   secret-encrypt --secret-key PROD_SECRET_KEY --in prod.env --out secrets/prod.env.enc --wrap 76
ephemeral "secret_secret" "django_env" {
  ciphertext = file("${path.module}/secrets/prod.env.enc")
}

# Asymmetric (age): encrypted with the public key only; the env var holds the
# private key AGE-SECRET-KEY-1... The method is detected from the prefix.
ephemeral "secret_secret" "stripe_key" {
  ciphertext = "AGE1;YWdlLWVuY3J5cHRpb24ub3JnL3Yx..."
  secret_key = "PROD_AGE_KEY"
}
