package opnsense

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// System → Firmware (/api/core/firmware). Package jobs run in the background on the firewall:
//
//	POST install/<pkg> | remove/<pkg> | reinstall/<pkg> | update   start a job → {"status":"ok","msg_uuid":...}
//	GET  upgradestatus   the job's log; status "running" until the log has ***DONE*** (or ***REBOOT***)
//	GET  running         "busy" while a job runs, "ready" otherwise
//	GET  info            every package and plugin, installed and available, with repository and tier
//	GET/POST status      update status; POST runs a synchronous check first
//
// The firewall runs one job at a time and keeps the last job's log, so a client must not
// mistake the *previous* job's ***DONE*** for its own. RunJob snapshots the log first.
//
// Adding package repositories (e.g. community repos) is not possible through the API.

var pkgNameRe = regexp.MustCompile(`^[a-zA-Z0-9._+-]+$`)

// ValidPackageName reports whether name is a plausible pkg name.
func ValidPackageName(name string) bool { return pkgNameRe.MatchString(name) }

// Package is a package or plugin as `info` reports it.
type Package struct {
	Name       Text `json:"name"`
	Version    Text `json:"version"`
	Comment    Text `json:"comment"`
	Size       Text `json:"flatsize"`
	Locked     Text `json:"locked"`
	Installed  Text `json:"installed"`  // "1" when installed
	Provided   Text `json:"provided"`   // "1" when a repository offers it
	Configured Text `json:"configured"` // "1" when listed in the config as a wanted plugin
	Repository Text `json:"repository"` // OPNsense, SunnyValley, or a community repo name
	// Tier is the support tier for plugins: 1 core team … 3 community; 4 means third-party,
	// orphaned or unknown (any repository other than OPNsense and SunnyValley).
	Tier Text `json:"tier"`
}

// IsInstalled reports whether the package is installed.
func (p Package) IsInstalled() bool { return p.Installed == "1" }

// ThirdParty reports whether the package comes from outside the official repositories.
func (p Package) ThirdParty() bool {
	return p.Repository != "" && p.Repository != "OPNsense" && p.Repository != "SunnyValley" && p.Repository != "N/A"
}

// FirmwareInfo is the product version plus all packages and plugins.
type FirmwareInfo struct {
	ProductID      Text      `json:"product_id"`
	ProductVersion Text      `json:"product_version"`
	Packages       []Package `json:"package"`
	Plugins        []Package `json:"plugin"`
}

// FirmwareStatus is the result of an update check.
type FirmwareStatus struct {
	// Status is "none" (never checked), "ok"/"none" (up to date), "update", "upgrade" or "error".
	Status         Text `json:"status"`
	Message        Text `json:"status_msg"`
	Updates        Text `json:"updates"`
	DownloadSize   Text `json:"download_size"`
	NeedsReboot    Text `json:"needs_reboot"`
	UpgradeMajor   Text `json:"upgrade_major_version"`
	UpgradeMessage Text `json:"upgrade_major_message"`
	Product        struct {
		Version Text `json:"product_version"`
		Latest  Text `json:"product_latest"`
	} `json:"product"`
	Packages []struct {
		Name       Text `json:"name"`
		Old        Text `json:"old"`
		New        Text `json:"new"`
		Reason     Text `json:"reason"`
		Repository Text `json:"repository"`
	} `json:"all_packages"`
}

// JobResult is the outcome of a background package job.
type JobResult struct {
	// Reboot is true when the job asked for a reboot (e.g. a kernel update).
	Reboot bool
	// Log is the job's output.
	Log string
}

// ErrFirmwareBusy is returned when another package job is running.
var ErrFirmwareBusy = errors.New("opnsense: another firmware/package job is running")

// FirmwareService manages packages and firmware updates.
type FirmwareService struct {
	c *Client
	// PollInterval is how often job status is polled (default 2s).
	PollInterval time.Duration
}

func newFirmwareService(c *Client) *FirmwareService { return &FirmwareService{c: c} }

// Info lists packages and plugins.
func (s *FirmwareService) Info(ctx context.Context) (*FirmwareInfo, error) {
	var info FirmwareInfo
	if err := s.c.Get(ctx, "core/firmware/info", &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// Find returns a package or plugin by exact name, or ErrNotFound.
func (s *FirmwareService) Find(ctx context.Context, name string) (*Package, error) {
	info, err := s.Info(ctx)
	if err != nil {
		return nil, err
	}
	for _, list := range [][]Package{info.Plugins, info.Packages} {
		for _, p := range list {
			if string(p.Name) == name {
				return &p, nil
			}
		}
	}
	return nil, ErrNotFound
}

// Status returns the update status. With check, the firewall first queries its mirror.
func (s *FirmwareService) Status(ctx context.Context, check bool) (*FirmwareStatus, error) {
	var st FirmwareStatus
	var err error
	if check {
		err = s.c.Post(ctx, "core/firmware/status", nil, &st)
	} else {
		err = s.c.Get(ctx, "core/firmware/status", &st)
	}
	if err != nil {
		return nil, err
	}
	return &st, nil
}

// Busy reports whether a package job is running.
func (s *FirmwareService) Busy(ctx context.Context) (bool, error) {
	var resp struct {
		Status string `json:"status"`
	}
	if err := s.c.Get(ctx, "core/firmware/running", &resp); err != nil {
		return false, err
	}
	return strings.TrimSpace(resp.Status) == "busy", nil
}

type jobStatus struct {
	Status string `json:"status"` // running, done, reboot, error
	Log    string `json:"log"`
}

func (s *FirmwareService) jobLog(ctx context.Context) (jobStatus, error) {
	var st jobStatus
	err := s.c.Get(ctx, "core/firmware/upgradestatus", &st)
	return st, err
}

// Install installs a package or plugin, waits for the job and checks that it is installed.
// pkg reports some failures (e.g. an unknown package) only in the log, with the job "done".
func (s *FirmwareService) Install(ctx context.Context, name string) (*JobResult, error) {
	res, err := s.runPackageJob(ctx, "install", name)
	if err != nil {
		return nil, err
	}
	return res, s.expectInstalled(ctx, name, true, res)
}

// Remove removes a package or plugin, waits for the job and checks that it is gone.
func (s *FirmwareService) Remove(ctx context.Context, name string) (*JobResult, error) {
	res, err := s.runPackageJob(ctx, "remove", name)
	if err != nil {
		return nil, err
	}
	return res, s.expectInstalled(ctx, name, false, res)
}

func (s *FirmwareService) expectInstalled(ctx context.Context, name string, want bool, res *JobResult) error {
	p, err := s.Find(ctx, name)
	installed := err == nil && p.IsInstalled()
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if installed == want {
		return nil
	}
	verb := "install"
	if !want {
		verb = "remove"
	}
	return fmt.Errorf("opnsense: could not %s %s: %s", verb, name, lastLines(res.Log, 3))
}

// Reinstall reinstalls a package and waits for the job to finish.
func (s *FirmwareService) Reinstall(ctx context.Context, name string) (*JobResult, error) {
	return s.runPackageJob(ctx, "reinstall", name)
}

// Update installs minor updates (not major upgrades) and waits for the job to finish. The
// result says whether a reboot is required; this client never reboots on its own.
func (s *FirmwareService) Update(ctx context.Context) (*JobResult, error) {
	return s.RunJob(ctx, "core/firmware/update")
}

func (s *FirmwareService) runPackageJob(ctx context.Context, action, name string) (*JobResult, error) {
	if !ValidPackageName(name) {
		return nil, fmt.Errorf("opnsense: invalid package name %q", name)
	}
	return s.RunJob(ctx, "core/firmware/"+action+"/"+url.PathEscape(name))
}

// RunJob starts a background job at path and waits until it finishes or ctx ends.
func (s *FirmwareService) RunJob(ctx context.Context, path string) (*JobResult, error) {
	if busy, err := s.Busy(ctx); err != nil {
		return nil, err
	} else if busy {
		return nil, ErrFirmwareBusy
	}
	before, err := s.jobLog(ctx) // the previous job's log, to tell it apart from ours
	if err != nil {
		return nil, err
	}

	var start struct {
		Status string `json:"status"`
	}
	if err := s.c.Post(ctx, path, nil, &start); err != nil {
		return nil, err
	}
	if start.Status != "ok" {
		return nil, fmt.Errorf("opnsense: %s: status %q", path, start.Status)
	}

	interval := s.PollInterval
	if interval == 0 {
		interval = 2 * time.Second
	}
	started := false
	for polls := 1; ; polls++ {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("opnsense: waiting for %s: %w (the job keeps running on the firewall)", path, ctx.Err())
		case <-time.After(interval):
		}
		st, err := s.jobLog(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("opnsense: waiting for %s: %w (the job keeps running on the firewall)", path, ctx.Err())
			}
			return nil, err
		}
		// Our job has started once the log differs from the previous job's, or it is running.
		if st.Log != before.Log || st.Status == "running" {
			started = true
		}
		// A job that printed exactly the previous log (e.g. "already installed" twice) is
		// recognised once the firewall reports it idle for a few polls.
		if !started && polls >= 3 {
			if busy, err := s.Busy(ctx); err == nil && !busy {
				started = true
			}
		}
		if !started {
			continue
		}
		switch st.Status {
		case "done":
			return &JobResult{Log: st.Log}, nil
		case "reboot":
			return &JobResult{Log: st.Log, Reboot: true}, nil
		case "error":
			return nil, fmt.Errorf("opnsense: %s failed: %s", path, lastLines(st.Log, 5))
		}
	}
}

// lastLines returns the last n non-empty lines of s.
func lastLines(s string, n int) string {
	var lines []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, strings.TrimSpace(l))
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

// LastLines exposes lastLines for callers that summarise job logs.
func LastLines(s string, n int) string { return lastLines(s, n) }
