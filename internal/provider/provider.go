package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

var _ provider.Provider = &secretProvider{}
var _ provider.ProviderWithEphemeralResources = &secretProvider{}

type secretProvider struct {
	version string
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
	// No provider-level config needed: each secret names its own key env var
	// via the secret_key attribute (default SECRET_KEY),
	// so the provider block stays empty
	resp.Schema = schema.Schema{
		Description: "Commit AES-256-GCM encrypted secrets to your repo and decrypt them on-the-fly during plan/apply. Each secret names the environment variable holding its key via secret_key (default SECRET_KEY), so different secrets can use different keys. Decrypted values never touch state (ephemeral).",
	}
}

func (p *secretProvider) Configure(_ context.Context, _ provider.ConfigureRequest, _ *provider.ConfigureResponse) {
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
	return nil
}
