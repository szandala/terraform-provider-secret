package provider

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ ephemeral.EphemeralResource              = &secretEphemeralResource{}
	_ ephemeral.EphemeralResourceWithConfigure = &secretEphemeralResource{}
)

func NewSecretEphemeralResource() ephemeral.EphemeralResource {
	return &secretEphemeralResource{}
}

type secretEphemeralResource struct {
	defaultSecretKey string
	configured       bool
}

// Config = what the user writes in the ephemeral block.
// Result = what Open returns; consumable but never persisted to state/plan.
type secretModel struct {
	Ciphertext  types.String `tfsdk:"ciphertext"`
	SecretKey   types.String `tfsdk:"secret_key"`
	Description types.String `tfsdk:"description"`
	Plaintext   types.String `tfsdk:"plaintext"`
}

func (r *secretEphemeralResource) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	// Conventional <provider>_<name>: "secret_secret".
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (r *secretEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Decrypts a value encrypted with secret-encrypt (AES256, XCHACHA20 or AGE1; detected from the prefix) on-the-fly. " +
			"The plaintext is ephemeral and never written to state or plan.",
		Attributes: map[string]schema.Attribute{
			"ciphertext": schema.StringAttribute{
				Required: true,
				Description: "The encrypted value, e.g. 'AES256;...' or 'AGE1;...'. Safe to commit to your repository. Whitespace is ignored, " +
					"so the value may be wrapped across lines or loaded with file().",
				Validators: []validator.String{ciphertextValidator{}},
			},
			"secret_key": schema.StringAttribute{
				Optional: true,
				Description: "Name of the environment variable that holds the key for this secret (e.g. \"PROD_SECRET_KEY\"): " +
					"the passphrase for AES256/XCHACHA20, the private key AGE-SECRET-KEY-1... for AGE1. " +
					"Defaults to the provider's secret_key, which defaults to \"SECRET_KEY\".",
				Validators: []validator.String{envVarNameValidator{}},
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

func (r *secretEphemeralResource) Configure(_ context.Context, req ephemeral.ConfigureRequest, resp *ephemeral.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	data, ok := req.ProviderData.(*providerData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected provider data",
			fmt.Sprintf("Expected *providerData, got %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}
	r.defaultSecretKey = data.defaultSecretKey
	r.configured = true
}

func (r *secretEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data secretModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Which env var holds the key for THIS secret:
	// resource secret_key > provider secret_key > SECRET_KEY.
	envName := data.SecretKey.ValueString()
	if envName == "" {
		envName = defaultSecretKey
		if r.configured {
			envName = r.defaultSecretKey
		}
	}
	if envName == "" {
		resp.Diagnostics.AddError(
			"Decryption key variable unknown",
			"The provider's secret_key is not known yet. Set secret_key to a literal string, "+
				"either in the provider block or on this secret.",
		)
		return
	}

	key, ok := os.LookupEnv(envName)
	if !ok || key == "" {
		resp.Diagnostics.AddError(
			"Decryption key not found",
			fmt.Sprintf("Environment variable %q is not set or empty. Export it before running plan/apply.", envName),
		)
		return
	}

	plaintext, err := Decrypt(key, data.Ciphertext.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to decrypt secret",
			fmt.Sprintf("Using the key from %q: %s", envName, err),
		)
		return
	}

	data.Plaintext = types.StringValue(plaintext)
	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)

	// No RenewAt / no private data: the value is derived deterministically from
	// config + env each time, so there's nothing to renew or clean up in Close.
}
