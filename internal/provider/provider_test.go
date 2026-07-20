package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/provider"
)

func TestProvider_Metadata(t *testing.T) {
	p := New("test")()
	resp := &provider.MetadataResponse{}
	p.Metadata(context.Background(), provider.MetadataRequest{}, resp)

	if resp.TypeName != "secret" {
		t.Fatalf("provider TypeName = %q, want %q", resp.TypeName, "secret")
	}
	if resp.Version != "test" {
		t.Fatalf("provider Version = %q, want %q", resp.Version, "test")
	}
}

func TestProvider_RegistersEphemeralResource(t *testing.T) {
	p := New("test")()

	ep, ok := p.(provider.ProviderWithEphemeralResources)
	if !ok {
		t.Fatal("provider does not implement ProviderWithEphemeralResources")
	}

	factories := ep.EphemeralResources(context.Background())
	if len(factories) != 1 {
		t.Fatalf("expected 1 ephemeral resource, got %d", len(factories))
	}
}

func TestSecretResource_Metadata(t *testing.T) {
	r := NewSecretEphemeralResource()
	resp := &ephemeral.MetadataResponse{}
	// ProviderTypeName is intentionally ignored — we force the bare "secret".
	r.Metadata(context.Background(), ephemeral.MetadataRequest{ProviderTypeName: "secret"}, resp)

	if resp.TypeName != "secret" {
		t.Fatalf("resource TypeName = %q, want %q", resp.TypeName, "secret")
	}
}

func TestSecretResource_Schema(t *testing.T) {
	r := NewSecretEphemeralResource()
	resp := &ephemeral.SchemaResponse{}
	r.Schema(context.Background(), ephemeral.SchemaRequest{}, resp)

	attrs := resp.Schema.Attributes

	tests := []struct {
		name      string
		required  bool
		optional  bool
		computed  bool
		sensitive bool
	}{
		{"ciphertext", true, false, false, false},
		{"secret_key", false, true, false, false},
		{"description", false, true, false, false},
		{"plaintext", false, false, true, true},
	}

	for _, tt := range tests {
		attr, ok := attrs[tt.name]
		if !ok {
			t.Errorf("missing attribute %q", tt.name)
			continue
		}
		if attr.IsRequired() != tt.required {
			t.Errorf("%s: IsRequired = %v, want %v", tt.name, attr.IsRequired(), tt.required)
		}
		if attr.IsOptional() != tt.optional {
			t.Errorf("%s: IsOptional = %v, want %v", tt.name, attr.IsOptional(), tt.optional)
		}
		if attr.IsComputed() != tt.computed {
			t.Errorf("%s: IsComputed = %v, want %v", tt.name, attr.IsComputed(), tt.computed)
		}
		if attr.IsSensitive() != tt.sensitive {
			t.Errorf("%s: IsSensitive = %v, want %v", tt.name, attr.IsSensitive(), tt.sensitive)
		}
	}
}
