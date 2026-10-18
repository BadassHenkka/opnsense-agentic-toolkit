package opnsense

import (
	"context"
	"net/url"
)

// System → Configuration → Backups and System → Snapshots (read only).
//
//	GET core/backup/backups/this            {"items":[{id,time,time_iso,description,username,filesize}]}, newest first
//	GET core/backup/diff/this/<b1>/<b2>     {"items":[unified diff lines]} (b2 is the older file)
//	GET core/snapshots/isSupported          {"supported":true} on ZFS
//	GET core/snapshots/search               rows {uuid,name,active,mountpoint,created,size,...}
//
// Downloading a backup is deliberately not offered: the file holds every secret of the firewall.
// Reverting and deleting backups, and creating or activating snapshots, are state changes the
// MCP server never makes.

// ConfigBackup is one saved config.xml revision.
type ConfigBackup struct {
	ID          string `json:"id"`
	Time        string `json:"time"`
	TimeISO     string `json:"time_iso"`
	Description string `json:"description"`
	Username    string `json:"username"`
	Filesize    Int    `json:"filesize"`
}

// Snapshot is a ZFS boot environment snapshot.
type Snapshot struct {
	UUID       string `json:"uuid"`
	Name       string `json:"name"`
	Active     string `json:"active"`
	Mountpoint string `json:"mountpoint"`
	Created    string `json:"created"`
	Size       string `json:"size"`
}

// BackupService reads configuration backups and snapshots.
type BackupService struct{ c *Client }

func newBackupService(c *Client) *BackupService { return &BackupService{c: c} }

// List returns the local config backups, newest first.
func (s *BackupService) List(ctx context.Context) ([]ConfigBackup, error) {
	var res struct {
		Items []ConfigBackup `json:"items"`
	}
	if err := s.c.Get(ctx, "core/backup/backups/this", &res); err != nil {
		return nil, err
	}
	return res.Items, nil
}

// Diff returns the unified diff from the older backup to the newer one (ids as in List).
func (s *BackupService) Diff(ctx context.Context, newer, older string) ([]string, error) {
	var res struct {
		Items []string `json:"items"`
	}
	if err := s.c.Get(ctx, "core/backup/diff/this/"+url.PathEscape(newer)+"/"+url.PathEscape(older), &res); err != nil {
		return nil, err
	}
	return res.Items, nil
}

// SnapshotsSupported reports whether the root file system is ZFS.
func (s *BackupService) SnapshotsSupported(ctx context.Context) (bool, error) {
	var res struct {
		Supported bool `json:"supported"`
	}
	if err := s.c.Get(ctx, "core/snapshots/isSupported", &res); err != nil {
		return false, err
	}
	return res.Supported, nil
}

// Snapshots lists the boot environment snapshots; empty when ZFS is not used.
func (s *BackupService) Snapshots(ctx context.Context) ([]Snapshot, error) {
	var res SearchResult[Snapshot]
	if err := s.c.Post(ctx, "core/snapshots/search", map[string]any{"current": 1, "rowCount": -1}, &res); err != nil {
		return nil, err
	}
	return res.Rows, nil
}
