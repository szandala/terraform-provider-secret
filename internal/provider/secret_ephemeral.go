package provider

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ ephemeral.EphemeralResource = &secretEphemeralResource{}

func NewSecretEphemeralResource() ephemeral.EphemeralResource {
	return &secretEphemeralResource{}
}

type secretEphemeralResource struct{}

// Config = what the user writes in the ephemeral block.
// Result = what Open returns; consumable but never persisted to state/plan.
type secretModel struct {
	Ciphertext  types.String `tfsdk:"ciphertext"`
	SecretKey   types.String `tfsdk:"secret_key"`
	Description types.String `tfsdk:"description"`
	Plaintext   types.String `tfsdk:"plaintext"`
}

func (r *secretEphemeralResource) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	// Bare "secret" rather than the conventional providerTypeName + "_secret"
	// (which would be "secret_secret"). Terraform only requires the type to be
	// prefixed by the provider name, and "secret" satisfies that against the
	// "secret" provider, so this is accepted.
	resp.TypeName = "secret"
}

func (r *secretEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Decrypts an AES-256-GCM encrypted value on-the-fly. The plaintext is ephemeral and never written to state or plan.",
		Attributes: map[string]schema.Attribute{
			"ciphertext": schema.StringAttribute{
				Required:    true,
				Description: "The 'SECRET1;...' encrypted value. Safe to commit to your repository.",
			},
			"secret_key": schema.StringAttribute{
				Optional:    true,
				Description: "Name of the environment variable that holds the passphrase for this secret (e.g. \"SECRET_KEY\", \"PROD_SECRET_KEY\", or \"TF_VAR_app_key\"). Defaults to \"SECRET_KEY\" if omitted.",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Free-form note describing what this secret is for. Purely informational; does not affect decryption.",
			},
			"plaintext": schema.StringAttribute{
				Computed:    true,
				Sensitive:   true,
				Description: "The decrypted value. Only available during plan/apply; never persisted.",
			},
		},
	}
}

func (r *secretEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data secretModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Which env var holds the passphrase for THIS secret. Defaults to SECRET_KEY.
	envName := data.SecretKey.ValueString()
	if envName == "" {
		envName = "SECRET_KEY"
	}

	passphrase, ok := os.LookupEnv(envName)
	if !ok || passphrase == "" {
		resp.Diagnostics.AddError(
			"Decryption key not found",
			fmt.Sprintf("Environment variable %q is not set or empty. Export it before running plan/apply.", envName),
		)
		return
	}

	plaintext, err := Decrypt(passphrase, data.Ciphertext.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to decrypt secret", err.Error())
		return
	}

	data.Plaintext = types.StringValue(plaintext)
	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)

	// No RenewAt / no private data: the value is derived deterministically from
	// config + env each time, so there's nothing to renew or clean up in Close.
}
