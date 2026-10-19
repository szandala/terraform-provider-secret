package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/function"
)

var _ function.Function = &writeOnlyVersionFunction{}

func NewWriteOnlyVersionFunction() function.Function {
	return &writeOnlyVersionFunction{}
}

// writeOnlyVersionFunction: provider::secret::wo_version(ciphertext) -> number
//
// Write-only arguments (secret_data_wo, password_wo, ...) are only re-sent when
// their *_wo_version changes. Bumping that by hand is easy to forget. The
// ciphertext is NOT ephemeral (it is a literal in the repo), so a version
// derived from it is allowed in a normal attribute, and it changes exactly
// when someone re-encrypts the secret.
type writeOnlyVersionFunction struct{}

func (f *writeOnlyVersionFunction) Metadata(_ context.Context, _ function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "wo_version"
}

func (f *writeOnlyVersionFunction) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary: "Derive a *_wo_version number from a ciphertext",
		Description: "Returns a stable positive integer derived from the SHA-256 of the ciphertext (whitespace ignored). " +
			"Use it as a *_wo_version argument so the write-only value is re-sent automatically whenever the secret " +
			"is re-encrypted. Hashes the ciphertext only; reveals nothing about the plaintext and needs no key.",
		Parameters: []function.Parameter{
			function.StringParameter{
				Name:        "ciphertext",
				Description: "The SECRET1;... value (the same one passed to secret_secret).",
			},
		},
		Return: function.Int64Return{},
	}
}

func (f *writeOnlyVersionFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var ciphertext string
	resp.Error = function.ConcatFuncErrors(resp.Error, req.Arguments.Get(ctx, &ciphertext))
	if resp.Error != nil {
		return
	}
	if err := ValidateCiphertext(ciphertext); err != nil {
		resp.Error = function.ConcatFuncErrors(resp.Error, function.NewArgumentFuncError(0, "invalid ciphertext: "+err.Error()))
		return
	}
	resp.Error = function.ConcatFuncErrors(resp.Error, resp.Result.Set(ctx, WriteOnlyVersion(ciphertext)))
}
