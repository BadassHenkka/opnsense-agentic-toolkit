package opnsensetest

import (
	"net/http"
	"sort"
	"strings"
)

// FakePackage is a package in the fake firmware catalog.
type FakePackage struct {
	Name, Version, Comment, Repository, Tier string
	Installed                                bool
}

// firmwareState simulates pkg jobs: a started job reports "running" for JobPolls status
// reads, then finishes. Only one job runs at a time, like on the firewall.
type firmwareState struct {
	catalog  map[string]*FakePackage
	log      string
	running  int // remaining "running" polls
	finish   func()
	reboot   bool
	jobPolls int
	update   *FakePackage // pending minor update, if any
}

// SetFirmwareJobPolls sets how many status reads a job stays running.
func (s *Server) SetFirmwareJobPolls(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.firmware.jobPolls = n
}

// AddPackage adds a package to the fake catalog (e.g. from a community repository).
func (s *Server) AddPackage(p FakePackage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := p
	s.firmware.catalog[p.Name] = &cp
}

// PackageInstalled reports whether a package is installed on the fake.
func (s *Server) PackageInstalled(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.firmware.catalog[name]
	return ok && p.Installed
}

// SetPendingUpdate makes a minor update available that requires a reboot when reboot is set.
func (s *Server) SetPendingUpdate(pkg, from, to string, reboot bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.firmware.update = &FakePackage{Name: pkg, Version: to, Comment: from}
	s.firmware.reboot = reboot
}

func registerFirmware(s *Server) {
	fw := &firmwareState{
		catalog: map[string]*FakePackage{
			"opnsense":        {Name: "opnsense", Version: "26.7.3", Repository: "OPNsense", Installed: true},
			"os-acme-client":  {Name: "os-acme-client", Version: "4.17", Comment: "ACME Client", Repository: "OPNsense", Tier: "2", Installed: true},
			"os-ddclient":     {Name: "os-ddclient", Version: "1.27", Comment: "Dynamic DNS client", Repository: "OPNsense", Tier: "2"},
			"os-theme-cicada": {Name: "os-theme-cicada", Version: "1.39", Comment: "Theme cicada", Repository: "OPNsense", Tier: "3"},
			"os-sensei":       {Name: "os-sensei", Version: "1.20", Comment: "Zenarmor", Repository: "SunnyValley", Tier: "1"},
		},
		log:      "***GOT REQUEST TO CHECK FOR UPDATES***\n***DONE***",
		jobPolls: 1,
	}
	s.firmware = fw

	pkgRow := func(p *FakePackage) map[string]string {
		inst := "0"
		if p.Installed {
			inst = "1"
		}
		tier := p.Tier
		if p.Repository != "OPNsense" && p.Repository != "SunnyValley" {
			tier = "4"
		}
		return map[string]string{"name": p.Name, "version": p.Version, "comment": p.Comment, "flatsize": "1.0MiB",
			"locked": "N/A", "installed": inst, "provided": "1", "configured": inst, "repository": p.Repository,
			"tier": tier, "path": p.Repository + "/" + p.Name}
	}
	startJob := func(w http.ResponseWriter, header string, done func() (string, bool)) {
		if fw.running > 0 {
			writeJSON(w, map[string]string{"status": "ok", "msg_uuid": "busy"}) // the real API also accepts it
			return
		}
		fw.log = header + "\n"
		fw.running = fw.jobPolls
		fw.finish = func() {
			out, reboot := done()
			fw.log += out + "\n"
			if reboot {
				fw.log += "***REBOOT***"
			} else {
				fw.log += "***DONE***"
			}
		}
		writeJSON(w, map[string]string{"status": "ok", "msg_uuid": "00000000-job"})
	}

	s.extra["core/firmware/info"] = func(_ *Server, w http.ResponseWriter, _ *http.Request, _ string) {
		names := make([]string, 0, len(fw.catalog))
		for n := range fw.catalog {
			names = append(names, n)
		}
		sort.Strings(names)
		var pkgs, plugins []map[string]string
		for _, n := range names {
			row := pkgRow(fw.catalog[n])
			pkgs = append(pkgs, row)
			if strings.HasPrefix(n, "os-") {
				plugins = append(plugins, row)
			}
		}
		writeJSON(w, map[string]any{"product_id": "opnsense", "product_version": "26.7.3",
			"package": pkgs, "plugin": plugins, "changelog": []any{}, "product": map[string]any{}})
	}
	s.extra["core/firmware/running"] = func(_ *Server, w http.ResponseWriter, _ *http.Request, _ string) {
		st := "ready"
		if fw.running > 0 {
			st = "busy"
		}
		writeJSON(w, map[string]string{"status": st})
	}
	s.extra["core/firmware/upgradestatus"] = func(_ *Server, w http.ResponseWriter, _ *http.Request, _ string) {
		if fw.running > 0 {
			fw.running--
			if fw.running == 0 && fw.finish != nil {
				fw.finish()
				fw.finish = nil
			} else {
				writeJSON(w, map[string]string{"status": "running", "log": fw.log})
				return
			}
		}
		st := "done"
		if strings.Contains(fw.log, "***REBOOT***") {
			st = "reboot"
		}
		writeJSON(w, map[string]string{"status": st, "log": fw.log})
	}
	s.extra["core/firmware/install"] = func(_ *Server, w http.ResponseWriter, _ *http.Request, name string) {
		startJob(w, "***GOT REQUEST TO INSTALL***", func() (string, bool) {
			p, ok := fw.catalog[name]
			if !ok {
				return "pkg: No packages available to install matching '" + name + "' have been found in the repositories", false
			}
			p.Installed = true
			return "Installing " + p.Name + "-" + p.Version + "...\n[1/1] Extracting " + p.Name + ": done", false
		})
	}
	s.extra["core/firmware/remove"] = func(_ *Server, w http.ResponseWriter, _ *http.Request, name string) {
		startJob(w, "***GOT REQUEST TO REMOVE***", func() (string, bool) {
			p, ok := fw.catalog[name]
			if !ok || !p.Installed {
				return "pkg: No packages matched for pattern '" + name + "'", false
			}
			p.Installed = false
			return "Deinstalling " + p.Name + "-" + p.Version + "...", false
		})
	}
	s.extra["core/firmware/update"] = func(_ *Server, w http.ResponseWriter, _ *http.Request, _ string) {
		startJob(w, "***GOT REQUEST TO UPDATE***", func() (string, bool) {
			if fw.update == nil {
				return "Your packages are up to date.", false
			}
			if p, ok := fw.catalog[fw.update.Name]; ok {
				p.Version = fw.update.Version
			}
			fw.update = nil
			return "Upgrading packages...", fw.reboot
		})
	}
	s.extra["core/firmware/status"] = func(_ *Server, w http.ResponseWriter, _ *http.Request, _ string) {
		if fw.update == nil {
			writeJSON(w, map[string]any{"status": "none", "status_msg": "There are no updates available on the selected mirror.",
				"updates": "0", "product": map[string]string{"product_version": "26.7.3", "product_latest": "26.7.3"}, "all_packages": []any{}})
			return
		}
		reboot := "0"
		if fw.reboot {
			reboot = "1"
		}
		writeJSON(w, map[string]any{"status": "update", "status_msg": "There are 1 updates available.",
			"updates": "1", "needs_reboot": reboot,
			"product": map[string]string{"product_version": "26.7.3", "product_latest": fw.update.Version},
			"all_packages": []map[string]string{{"name": fw.update.Name, "old": fw.update.Comment,
				"new": fw.update.Version, "reason": "upgrade", "repository": "OPNsense"}}})
	}
}
