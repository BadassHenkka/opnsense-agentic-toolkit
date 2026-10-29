// Command terraform-provider-opnsense is the OPNsense Terraform provider.
//
// `terraform-provider-opnsense privileges [-resources a,b]` prints the OPNsense privileges the
// resources need, for setting up a least-privilege API user.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/smulis/opnsense-agentic-toolkit/internal/buildinfo"
	"github.com/smulis/opnsense-agentic-toolkit/internal/privileges"
	"github.com/smulis/opnsense-agentic-toolkit/internal/provider"
)

// version is set at build time with -ldflags "-X main.version=..."; main falls back to the
// module version (buildinfo.Version).
var version = "dev"

func main() {
	version = buildinfo.Version(version)
	if len(os.Args) > 1 && os.Args[1] == "privileges" {
		if err := runPrivileges(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
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

// runPrivileges prints the privileges the resource types in -resources need.
func runPrivileges(args []string) error {
	fs := flag.NewFlagSet("privileges", flag.ExitOnError)
	types := fs.String("resources", "all", "comma-separated resource types, e.g. opnsense_firewall_rule,opnsense_wireguard_peer")
	verbose := fs.Bool("v", false, "also list the endpoints each privilege is needed for")
	_ = fs.Parse(args)

	known := provider.ResourceTypes()
	want := known
	if *types != "all" {
		want = nil
		for _, t := range strings.Split(*types, ",") {
			if t = strings.TrimSpace(t); !slices.Contains(known, t) {
				return fmt.Errorf("unknown resource type %q", t)
			}
			want = append(want, t)
		}
	}
	var endpoints []string
	for _, t := range want {
		endpoints = append(endpoints, privileges.ResourceEndpoints(t)...)
	}
	fmt.Printf("Privileges for %d resource types:\n\n", len(want))
	return privileges.Write(os.Stdout, privileges.For(endpoints), *verbose)
}
