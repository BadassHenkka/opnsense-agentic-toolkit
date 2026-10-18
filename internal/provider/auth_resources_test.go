package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense/opnsensetest"
)

func TestAuthUserGroupsAndAPIKey(t *testing.T) {
	fake := opnsensetest.New(t)
	gh := newHarness(t, fake, NewGroupResource())
	var g genGroupModel
	if _, ok := gh.create(genGroupPlan(), &g); !ok {
		t.Fatal("group create failed")
	}
	if g.Gid.ValueString() == "" || g.Scope.ValueString() != "user" {
		t.Fatalf("gid %v scope %v", g.Gid, g.Scope)
	}

	uh := newHarness(t, fake, NewUserResource())
	up := genUserPlan()
	up.Groups = strSet(g.Gid.ValueString())
	var u genUserModel
	if _, ok := uh.create(up, &u); !ok {
		t.Fatal("user create failed")
	}
	c := fake.Client(t)
	grp, err := c.Auth.Groups.Get(context.Background(), g.ID.ValueString())
	if err != nil || len(grp.Members) != 1 || grp.Members[0] != u.Uid.ValueString() {
		t.Fatalf("members %+v, err %v; want uid %v", grp, err, u.Uid)
	}

	kh := newHarness(t, fake, NewAuthAPIKeyResource())
	var k authAPIKeyModel
	st, ok := kh.create(authAPIKeyModel{ID: types.StringUnknown(), User: types.StringValue("terraform"),
		Key: types.StringUnknown(), Secret: types.StringUnknown()}, &k)
	if !ok || k.Key.ValueString() == "" || k.Secret.ValueString() == "" {
		t.Fatalf("key %+v", k)
	}
	if _, ok := kh.read(st, &k); !ok || k.User.ValueString() != "terraform" || k.Secret.IsNull() {
		t.Fatalf("read %+v", k)
	}
	if id, ok := kh.importID(k.Key.ValueString()); !ok || id != k.Key.ValueString() {
		t.Fatalf("import %q", id)
	}
	kh.delete(st)
	if _, ok := kh.read(st, &k); ok {
		t.Fatal("deleted key still read")
	}
	if _, err := c.Auth.AddAPIKey(context.Background(), "nobody"); err == nil {
		t.Fatal("key for unknown user")
	}
}
