package main

// emitUnmanaged writes the table internal/unmanaged uses to list the live objects of each
// generated item resource, and the settings resources it has nothing to list for.
func emitUnmanaged(areas []*Area) string {
	b := newW()
	b.use("context")
	b.use(modulePath + "/internal/opnsense")
	b.p("// generatedListers lists the live objects of every generated item resource, by Terraform type.")
	b.p("func generatedListers() map[string]lister {")
	b.p("\treturn map[string]lister{")
	for _, a := range areas {
		for _, o := range a.Items {
			b.p("\t\t\"opnsense_%s\": func(ctx context.Context, c *opnsense.Client) ([]Object, error) {", o.Resource)
			b.p("\t\t\treturn items(ctx, c.%s.%s)", a.Service, o.Plural)
			b.p("\t\t},")
		}
	}
	b.p("\t}")
	b.p("}")
	b.p("")
	b.p("// settingsTypes are the generated settings resources: one fixed object each, nothing to list.")
	b.p("var settingsTypes = map[string]bool{")
	for _, a := range areas {
		for _, o := range a.Settings {
			b.p("\t\"opnsense_%s\": true,", o.Resource)
		}
	}
	b.p("}")
	return b.file("unmanaged", "gen/specs")
}
