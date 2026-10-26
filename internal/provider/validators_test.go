package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func runStringValidator(v validator.String, value types.String) *validator.StringResponse {
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), validator.StringRequest{
		Path:        path.Root("x"),
		ConfigValue: value,
	}, resp)
	return resp
}

func TestEnvVarNameValidator(t *testing.T) {
	for _, ok := range []string{"SECRET_KEY", "PROD_SECRET_KEY", "_x", "TF_VAR_app_key", "a1"} {
		if resp := runStringValidator(envVarNameValidator{}, types.StringValue(ok)); resp.Diagnostics.HasError() {
			t.Errorf("%q rejected: %v", ok, resp.Diagnostics)
		}
	}
	for _, bad := range []string{"my secret passphrase", "1ABC", "PROD-KEY", "$SECRET_KEY", "a=b"} {
		resp := runStringValidator(envVarNameValidator{}, types.StringValue(bad))
		if !resp.Diagnostics.HasError() {
			t.Errorf("%q accepted, want error", bad)
			continue
		}
		// The value might be the passphrase: it must never be echoed back.
		for _, d := range resp.Diagnostics {
			if strings.Contains(d.Summary()+d.Detail(), bad) {
				t.Errorf("diagnostic leaks the configured value %q", bad)
			}
		}
	}
	for _, v := range []types.String{types.StringNull(), types.StringUnknown()} {
		if resp := runStringValidator(envVarNameValidator{}, v); resp.Diagnostics.HasError() {
			t.Errorf("null/unknown must be skipped, got %v", resp.Diagnostics)
		}
	}
}

func TestCiphertextValidator(t *testing.T) {
	wire, err := Encrypt("aes256", "key", "value")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if resp := runStringValidator(ciphertextValidator{}, types.StringValue(wire+"\n")); resp.Diagnostics.HasError() {
		t.Fatalf("valid ciphertext rejected: %v", resp.Diagnostics)
	}
	if resp := runStringValidator(ciphertextValidator{}, types.StringValue("plain password")); !resp.Diagnostics.HasError() {
		t.Fatal("plaintext accepted as ciphertext")
	}
	if resp := runStringValidator(ciphertextValidator{}, types.StringUnknown()); resp.Diagnostics.HasError() {
		t.Fatal("unknown must be skipped")
	}
}
