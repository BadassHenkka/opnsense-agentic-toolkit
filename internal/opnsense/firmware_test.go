package opnsense_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense"
	"github.com/smulis/opnsense-agentic-toolkit/internal/opnsense/opnsensetest"
)

func fastFirmware(t *testing.T) (*opnsensetest.Server, *opnsense.FirmwareService) {
	fake := opnsensetest.New(t)
	fw := fake.Client(t).Firmware
	fw.PollInterval = 5 * time.Millisecond
	return fake, fw
}

func TestFirmwareInstallRemove(t *testing.T) {
	ctx := context.Background()
	fake, fw := fastFirmware(t)
	fake.SetFirmwareJobPolls(3)

	p, err := fw.Find(ctx, "os-ddclient")
	if err != nil || p.IsInstalled() || p.ThirdParty() || p.Tier != "2" {
		t.Fatalf("before: %+v, %v", p, err)
	}
	res, err := fw.Install(ctx, "os-ddclient")
	if err != nil || res.Reboot || !strings.Contains(res.Log, "Extracting os-ddclient") {
		t.Fatalf("install: %+v, %v", res, err)
	}
	if !fake.PackageInstalled("os-ddclient") {
		t.Fatal("not installed")
	}

	// Installing again prints the same log as before; the job must still be recognised.
	if _, err := fw.Install(ctx, "os-ddclient"); err != nil {
		t.Fatalf("second install: %v", err)
	}

	if _, err := fw.Remove(ctx, "os-ddclient"); err != nil || fake.PackageInstalled("os-ddclient") {
		t.Fatalf("remove: %v", err)
	}

	// pkg reports an unknown package only in the log; Install turns that into an error.
	_, err = fw.Install(ctx, "os-does-not-exist")
	if err == nil || !strings.Contains(err.Error(), "No packages available") {
		t.Fatalf("unknown package: %v", err)
	}
	if _, err := fw.Install(ctx, "bad name; rm -rf"); err == nil {
		t.Fatal("invalid package name accepted")
	}
	if _, err := fw.Find(ctx, "nope"); !errors.Is(err, opnsense.ErrNotFound) {
		t.Fatalf("Find unknown: %v", err)
	}
}

func TestFirmwareThirdPartyAndUpdate(t *testing.T) {
	ctx := context.Background()
	fake, fw := fastFirmware(t)
	fake.AddPackage(opnsensetest.FakePackage{Name: "os-adguardhome-maxit", Version: "1.19",
		Comment: "AdGuard Home", Repository: "mimugmail"})
	p, err := fw.Find(ctx, "os-adguardhome-maxit")
	if err != nil || !p.ThirdParty() || p.Tier != "4" {
		t.Fatalf("community plugin: %+v, %v", p, err)
	}

	st, err := fw.Status(ctx, true)
	if err != nil || st.Status != "none" {
		t.Fatalf("status: %+v, %v", st, err)
	}
	fake.SetPendingUpdate("opnsense", "26.7.3", "26.7.4", true)
	st, _ = fw.Status(ctx, true)
	if st.Status != "update" || st.NeedsReboot != "1" || len(st.Packages) != 1 {
		t.Fatalf("status with update: %+v", st)
	}
	res, err := fw.Update(ctx)
	if err != nil || !res.Reboot {
		t.Fatalf("update: %+v, %v", res, err)
	}
}

func TestFirmwareBusy(t *testing.T) {
	ctx := context.Background()
	fake, fw := fastFirmware(t)
	fake.SetFirmwareJobPolls(1000)
	short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if _, err := fw.Install(short, "os-ddclient"); err == nil || !strings.Contains(err.Error(), "keeps running") {
		t.Fatalf("timeout: %v", err)
	}
	if _, err := fw.Install(ctx, "os-theme-cicada"); !errors.Is(err, opnsense.ErrFirmwareBusy) {
		t.Fatalf("want busy, got %v", err)
	}
}
