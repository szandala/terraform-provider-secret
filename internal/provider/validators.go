package provider

import (
	"context"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

const defaultSecretKey = "SECRET_KEY"

var envVarNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// envVarNameValidator makes sure secret_key holds the NAME of a variable.
//
// The most likely mistake is pasting the key itself into secret_key.
// The error message therefore never echoes the configured value, so it cannot
// end up in CI logs.
type envVarNameValidator struct{}

var _ validator.String = envVarNameValidator{}

func (envVarNameValidator) Description(_ context.Context) string {
	return "must be the name of an environment variable (letters, digits, underscores; not starting with a digit)"
}

func (v envVarNameValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (envVarNameValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if !envVarNameRe.MatchString(req.ConfigValue.ValueString()) {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid environment variable name",
			"secret_key must be the NAME of the environment variable that holds the key "+
				"(e.g. \"PROD_SECRET_KEY\"), not the key itself. "+
				"The configured value is not shown here in case it is the key.",
		)
	}
}

// ciphertextValidator checks the "<METHOD>;..." format at validate time, without a key,
// so `terraform validate` catches truncated or mangled values in review.
type ciphertextValidator struct{}

var _ validator.String = ciphertextValidator{}

func (ciphertextValidator) Description(_ context.Context) string {
	return "must be an AES256;... / XCHACHA20;... / AGE1;... value produced by secret-encrypt"
}

func (v ciphertextValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (ciphertextValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if err := ValidateCiphertext(req.ConfigValue.ValueString()); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid ciphertext", err.Error())
	}
}
