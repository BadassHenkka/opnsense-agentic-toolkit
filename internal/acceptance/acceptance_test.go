// Package acceptance runs the client against a real OPNsense firewall when OPNSENSE_ACC=1; the
// connection comes from the usual OPNSENSE_URL, OPNSENSE_API_KEY, OPNSENSE_API_SECRET (and
// OPNSENSE_CA_FILE or OPNSENSE_INSECURE). Without it the same tests run against the fake
// server, so the tests themselves stay working in every `go test`.
//
//	OPNSENSE_ACC=1 go test ./internal/acceptance -v                     read-only: safe on any firewall
//	OPNSENSE_ACC=1 OPNSENSE_ACC_WRITE=1 go test ./internal/acceptance -v  also create/update/delete test objects
//
// Read-only tests list every item collection and read every settings section the client knows
// (found by reflection, so new generated areas are covered automatically), and compare the
// firewall's field names with the Go structs (schema drift). Plugins that are not installed are
// skipped. Write tests only touch objects named acc-test-*, use documentation addresses
// (192.0.2.0/24) and the reserved .invalid domain, and delete what they create. Run them on a
// test VM, not on the firewall the house depends on.
package acceptance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense/opnsensetest"
)

func live() bool { return os.Getenv("OPNSENSE_ACC") == "1" }

func client(t *testing.T) *opnsense.Client {
	t.Helper()
	if !live() {
		return opnsensetest.New(t).Client(t)
	}
	c, err := opnsense.NewClient(opnsense.ConfigFromEnv())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func writes(t *testing.T) {
	t.Helper()
	if live() && os.Getenv("OPNSENSE_ACC_WRITE") != "1" {
		t.Skip("write test: set OPNSENSE_ACC_WRITE=1 (use a test VM)")
	}
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	return c
}

// notInstalled reports a 404, which is what an endpoint of a missing plugin returns.
func notInstalled(err error) bool { return errors.Is(err, opnsense.ErrNotFound) }

func TestAccFirmwareInfo(t *testing.T) {
	c := client(t)
	info, err := c.Firmware.Info(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s %s, %d plugins available", info.ProductID, info.ProductVersion, len(info.Plugins))
	if !strings.HasPrefix(string(info.ProductVersion), "26.7") {
		t.Logf("note: the models are pinned to 26.7.7 (gen/models/REFS); drift is expected on %s", info.ProductVersion)
	}
}

// endpoint is one item collection or settings section found on the client.
type endpoint struct {
	name string        // e.g. Firewall.Aliases
	ctl  reflect.Value // *ItemController[T, S] or *SettingsController[T]
}

// endpoints walks the client's services (including the embedded generated ones) and returns
// every ItemController and SettingsController field.
func endpoints(c *opnsense.Client) []endpoint {
	var out []endpoint
	var walkServices func(v reflect.Value)
	walkServices = func(v reflect.Value) {
		for i := 0; i < v.NumField(); i++ {
			f, sf := v.Field(i), v.Type().Field(i)
			if sf.Anonymous && f.Kind() == reflect.Struct {
				walkServices(f)
				continue
			}
			if !sf.IsExported() || f.Kind() != reflect.Pointer || f.IsNil() || f.Elem().Kind() != reflect.Struct {
				continue
			}
			svc := f.Elem()
			for j := 0; j < svc.NumField(); j++ {
				cf := svc.Field(j)
				if !svc.Type().Field(j).IsExported() || cf.Kind() != reflect.Pointer || cf.IsNil() {
					continue
				}
				tn := cf.Type().Elem().Name()
				if strings.HasPrefix(tn, "ItemController[") || strings.HasPrefix(tn, "SettingsController[") {
					out = append(out, endpoint{name: sf.Name + "." + svc.Type().Field(j).Name, ctl: cf})
				}
			}
		}
	}
	walkServices(reflect.ValueOf(c).Elem())
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

func call(ctl reflect.Value, method string, args ...any) (reflect.Value, error) {
	in := make([]reflect.Value, len(args))
	for i, a := range args {
		in[i] = reflect.ValueOf(a)
	}
	out := ctl.MethodByName(method).Call(in)
	err, _ := out[len(out)-1].Interface().(error)
	return out[0], err
}

// jsonFields returns the top-level JSON names of a struct type.
func jsonFields(t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name != "" && name != "-" {
			out = append(out, name)
		}
	}
	return out
}

// drift compares the struct's fields with the keys the firewall sent. A field the struct has
// but the firewall lacks is an error (the release removed or renamed it); keys only the
// firewall has are logged, since the specs skip some fields on purpose.
func drift(t *testing.T, st reflect.Type, keys map[string]json.RawMessage) {
	t.Helper()
	var extra []string
	for k := range keys {
		if !slices.Contains(jsonFields(st), k) {
			extra = append(extra, k)
		}
	}
	for _, f := range jsonFields(st) {
		if _, ok := keys[f]; !ok {
			t.Errorf("%s: field %q is not in the firewall's response (renamed or removed?)", st.Name(), f)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		t.Logf("%s: not modelled: %s", st.Name(), strings.Join(extra, ", "))
	}
}

// TestAccReadEverything lists every collection and reads every settings section.
func TestAccReadEverything(t *testing.T) {
	c := client(t)
	eps := endpoints(c)
	if len(eps) < 50 {
		t.Fatalf("found only %d endpoints by reflection; the walk is broken", len(eps))
	}
	for _, ep := range eps {
		t.Run(ep.name, func(t *testing.T) {
			cx := ctx(t)
			if ep.ctl.MethodByName("Template").IsValid() {
				res, err := call(ep.ctl, "Search", cx, "")
				if notInstalled(err) {
					t.Skip("not installed")
				}
				if err != nil {
					t.Fatalf("search: %v", err)
				}
				t.Logf("%d items", res.Elem().FieldByName("Total").Int())
				// The template is the add dialog's blank item: safe to read, and it has every field.
				tmpl, err := call(ep.ctl, "Template", cx)
				if err != nil {
					t.Fatalf("template: %v", err)
				}
				itemType := ep.ctl.MethodByName("Get").Type().Out(0).Elem()
				drift(t, itemType, tmpl.Interface().(map[string]json.RawMessage))
				return
			}
			v, err := call(ep.ctl, "Get", cx)
			if notInstalled(err) {
				t.Skip("not installed")
			}
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			// Fetch the section again as raw JSON to compare the field names.
			sectionKeys, err := settingsKeys(cx, c, ep.ctl)
			if err != nil {
				t.Fatalf("raw get: %v", err)
			}
			drift(t, v.Type().Elem(), sectionKeys)
		})
	}
}

// settingsKeys fetches a settings section as raw JSON.
func settingsKeys(cx context.Context, c *opnsense.Client, ctl reflect.Value) (map[string]json.RawMessage, error) {
	getPath := ctl.Elem().FieldByName("GetPath").String()
	path := ctl.Elem().FieldByName("Path").Interface().([]string)
	var raw json.RawMessage
	if err := c.Get(cx, getPath, &raw); err != nil {
		return nil, err
	}
	for _, key := range path {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("%s: no object at %q", getPath, key)
		}
		raw = m[key]
	}
	var out map[string]json.RawMessage
	return out, json.Unmarshal(raw, &out)
}

func TestAccLiveStatus(t *testing.T) {
	c := client(t)
	cx := ctx(t)
	if gws, err := c.Routing.GatewayStatus(cx); err != nil {
		t.Errorf("gateway status: %v", err)
	} else {
		t.Logf("%d gateways", len(gws))
	}
	if backups, err := c.Backup.List(cx); err != nil {
		t.Errorf("backups: %v", err)
	} else {
		t.Logf("%d config backups", len(backups))
	}
	if _, err := c.Backup.SnapshotsSupported(cx); err != nil {
		t.Errorf("snapshots: %v", err)
	}
	if _, err := c.Filter.Interfaces(cx); err != nil {
		t.Errorf("filter interfaces: %v", err)
	}
}

// testName is unique per run so a crashed run never collides with the next one.
func testName(prefix string) string {
	return fmt.Sprintf("%s%d", prefix, time.Now().Unix()%1_000_000)
}

// roundTrip runs add → get → set → get → delete on one collection and checks that what
// OPNsense stores is what was sent (check compares the fields the test cares about).
func roundTrip[T, S any](t *testing.T, ic *opnsense.ItemController[T, S], item T, update func(*T), check func(t *testing.T, want, got *T), apply bool) {
	t.Helper()
	cx := ctx(t)
	id, err := ic.Add(cx, item)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	deleted := false
	t.Cleanup(func() {
		if !deleted {
			_ = ic.Delete(context.Background(), id)
			if apply {
				_ = ic.Apply(context.Background())
			}
		}
	})
	if apply {
		if err := ic.Apply(cx); err != nil {
			t.Fatalf("apply after add: %v", err)
		}
	}
	got, err := ic.Get(cx, id)
	if err != nil {
		t.Fatalf("get after add: %v", err)
	}
	check(t, &item, got)

	update(got)
	if err := ic.Set(cx, id, *got); err != nil {
		t.Fatalf("set: %v", err)
	}
	again, err := ic.Get(cx, id)
	if err != nil {
		t.Fatalf("get after set: %v", err)
	}
	check(t, got, again)

	// Writing back exactly what was read must not change anything (no normalisation loop).
	if err := ic.Set(cx, id, *again); err != nil {
		t.Fatalf("set unchanged: %v", err)
	}
	if third, err := ic.Get(cx, id); err != nil || !reflect.DeepEqual(third, again) {
		t.Errorf("writing back what was read changed the item:\nbefore %+v\nafter  %+v (err %v)", again, third, err)
	}

	if err := ic.Delete(cx, id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	deleted = true
	if apply {
		if err := ic.Apply(cx); err != nil {
			t.Fatalf("apply after delete: %v", err)
		}
	}
	if _, err := ic.Get(cx, id); !errors.Is(err, opnsense.ErrNotFound) {
		t.Errorf("get after delete: %v, want ErrNotFound", err)
	}
}

func TestAccFirewallAlias(t *testing.T) {
	c := client(t)
	writes(t)
	alias := opnsense.Alias{Enabled: true, Name: testName("acc_test_"), Type: "host",
		Content: opnsense.LineList{"192.0.2.10"}, Description: "opnsense-agentic-toolkit acceptance test"}
	roundTrip(t, c.Firewall.Aliases, alias,
		func(a *opnsense.Alias) { a.Content = append(a.Content, "192.0.2.11") },
		func(t *testing.T, want, got *opnsense.Alias) {
			if got.Name != want.Name || got.Type != want.Type || !slices.Equal(got.Content, want.Content) {
				t.Errorf("alias stored as %+v, want %+v", got, want)
			}
		}, true)
}

func TestAccCronJob(t *testing.T) {
	c := client(t)
	writes(t)
	job := opnsense.CronJob{Origin: "cron", Enabled: false, Minutes: "0", Hours: "3", Days: "*", Months: "*", Weekdays: "*",
		Who: "root", Command: "firmware changelog cron", Description: testName("acc-test-")}
	roundTrip(t, c.System.CronJobs, job,
		func(j *opnsense.CronJob) { j.Hours = "4" },
		func(t *testing.T, want, got *opnsense.CronJob) {
			if got.Hours != want.Hours || got.Command != want.Command || got.Description != want.Description || got.Enabled != want.Enabled {
				t.Errorf("cron job stored as %+v, want %+v", got, want)
			}
		}, true)
}

// Unbound is not applied: a reconfigure restarts the resolver. The change is staged and
// deleted again, so the running DNS never sees it.
func TestAccUnboundHostOverride(t *testing.T) {
	c := client(t)
	writes(t)
	h := opnsense.HostOverride{Enabled: false, Hostname: testName("acc-test-"), Domain: "invalid", RR: "A",
		Server: "192.0.2.20", Description: "opnsense-agentic-toolkit acceptance test"}
	roundTrip(t, c.Unbound.HostOverrides, h,
		func(h *opnsense.HostOverride) { h.Server = "192.0.2.21" },
		func(t *testing.T, want, got *opnsense.HostOverride) {
			if got.Hostname != want.Hostname || got.Domain != want.Domain || got.Server != want.Server || got.RR != want.RR {
				t.Errorf("host override stored as %+v, want %+v", got, want)
			}
		}, false)
}
