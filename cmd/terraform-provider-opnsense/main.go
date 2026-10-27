// Command terraform-provider-opnsense is the OPNsense Terraform provider.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/smulis/opnsense-agentic-toolkit/internal/buildinfo"
	"github.com/smulis/opnsense-agentic-toolkit/internal/provider"
)

// version is set at build time with -ldflags "-X main.version=..."; main falls back to the
// module version (buildinfo.Version).
var version = "dev"

func main() {
	version = buildinfo.Version(version)
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run with support for debuggers like delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		// Local development address; see examples/terraform for the dev_overrides block.
		Address: "registry.terraform.io/smulis/opnsense",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
