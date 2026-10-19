terraform {
  required_version = ">= 1.11" # ephemeral resources (1.10) + write-only arguments (1.11)

  required_providers {
    secret = {
      source = "szandala/secret"
    }
  }
}

# Optional: env var used by every secret_secret that doesn't set its own
# secret_key. One root module per environment -> set it once here.
provider "secret" {
  secret_key = "PROD_SECRET_KEY"
}
