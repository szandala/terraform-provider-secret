package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ provider.Provider                       = &secretProvider{}
	_ provider.ProviderWithEphemeralResources = &secretProvider{}
	_ provider.ProviderWithFunctions          = &secretProvider{}
)

type secretProvider struct {
	version string
}

type secretProviderModel struct {
	SecretKey types.String `tfsdk:"secret_key"`
}

// providerData is handed to ephemeral resources in Configure.
type providerData struct {
	// defaultSecretKey is the env var name used when a secret does not set
	// its own secret_key. Empty means "unknown at this point" (see Open).
	defaultSecretKey string
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &secretProvider{version: version}
	}
}

func (p *secretProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "secret"
	resp.Version = p.version
}

func (p *secretProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Commit AES-256-GCM encrypted secrets to your repo and decrypt them on-the-fly during plan/apply, " +
			"ansible-vault style. The passphrase comes from an environment variable. Decrypted values are ephemeral " +
			"and never touch state or plan.",
		Attributes: map[string]schema.Attribute{
			"secret_key": schema.StringAttribute{
				Optional: true,
				Description: "Name of the environment variable holding the passphrase for every secret_secret that does " +
					"not set its own secret_key. Defaults to \"SECRET_KEY\". Handy for one root module per environment, " +
					"e.g. \"PROD_SECRET_KEY\" in the prod root.",
				Validators: []validator.String{envVarNameValidator{}},
			},
		},
	}
}

func (p *secretProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg secretProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	data := &providerData{defaultSecretKey: defaultSecretKey}
	switch {
	case cfg.SecretKey.IsUnknown():
		data.defaultSecretKey = ""
	case !cfg.SecretKey.IsNull() && cfg.SecretKey.ValueString() != "":
		data.defaultSecretKey = cfg.SecretKey.ValueString()
	}
	resp.EphemeralResourceData = data
}

func (p *secretProvider) EphemeralResources(_ context.Context) []func() ephemeral.EphemeralResource {
	return []func() ephemeral.EphemeralResource{
		NewSecretEphemeralResource,
	}
}

func (p *secretProvider) Resources(_ context.Context) []func() resource.Resource {
	return nil
}

func (p *secretProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

func (p *secretProvider) Functions(_ context.Context) []func() function.Function {
	return []func() function.Function{
		NewWriteOnlyVersionFunction,
	}
}
