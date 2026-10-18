# opnsense-agentic-toolkit

Let an AI agent work on an OPNsense firewall without giving up review and reproducibility.

The idea is three steps with a clear owner for each:

1. **Explore (MCP).** The agent reads the live state as freely as it likes: rules, aliases, DNS,
   routes, WireGuard handshakes, backups and diffs. The server runs read-only by default in the
   examples, so exploring cannot break anything.
2. **Verify (MCP, optional).** When the agent needs to know whether an idea works, it may make a
   short-lived trial change through the MCP write tools (staged, applied only on request), look at
   the result, and undo it. Trial changes are scaffolding, not the result.
3. **Implement (Terraform).** The proposed end state is written as Terraform. You review the plan
   and apply it. Terraform state is the source of truth for what the firewall should look like.

One Go OPNsense API client is shared by both front ends, so an endpoint and its quirks are written
once:

- **`mcp-opnsense`**: local MCP server (stdio) for steps 1 and 2.
- **`terraform-provider-opnsense`**: Terraform provider (Plugin Framework, protocol 6) for step 3.

## Terraform provider

```sh
make install-tf   # builds into $(go env GOPATH)/bin
```

Add a dev override in `~/.terraformrc` (skip `terraform init` for this provider):

```hcl
provider_installation {
  dev_overrides {
    "registry.terraform.io/smulis/opnsense" = "/Users/<you>/go/bin"
  }
  direct {}
}
```

Then see [examples/terraform/main.tf](examples/terraform/main.tf). Existing objects import by
name or UUID:

```sh
```
