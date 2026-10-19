locals {
  django_env_ct = file("${path.module}/secrets/prod.env.enc")
}

ephemeral "secret_secret" "django_env" {
  ciphertext = local.django_env_ct
}

resource "google_secret_manager_secret_version" "django_env" {
  secret         = google_secret_manager_secret.django_env.id
  secret_data_wo = ephemeral.secret_secret.django_env.plaintext

  # Changes exactly when the file is re-encrypted -> the new value is pushed.
  secret_data_wo_version = provider::secret::wo_version(local.django_env_ct)
}
