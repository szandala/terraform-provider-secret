package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/szandala/terraform-provider-secret/internal/provider"
)

// Set by goreleaser at build time.
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run with support for debuggers like delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		// This must match the source address users put in required_providers.
		Address: "registry.terraform.io/szandala/secret",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err.Error())
	}
}
