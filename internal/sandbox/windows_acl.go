package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type WindowsACLAction string

const (
	WindowsACLAllowWrite WindowsACLAction = "allow-write"
	WindowsACLDenyRead   WindowsACLAction = "deny-read"
	WindowsACLDenyWrite  WindowsACLAction = "deny-write"
)

type WindowsACLEntry struct {
	Action      WindowsACLAction `json:"action"`
	Path        string           `json:"path"`
	Capability  string           `json:"capability"`
	Materialize bool             `json:"materialize,omitempty"`
}

type WindowsACLPlan struct {
	Entries []WindowsACLEntry `json:"entries"`
}

func BuildWindowsACLPlan(config WindowsSandboxCommandConfig) (WindowsACLPlan, error) {
	if config.PermissionProfile.FileSystem.Kind != FileSystemRestricted {
		return WindowsACLPlan{}, errors.New("windows ACL setup requires a restricted filesystem permission profile")
	}
	writeCapabilities, err := windowsWriteRootCapabilities(config)
	if err != nil {
		return WindowsACLPlan{}, err
	}
	var entries []WindowsACLEntry
	for _, capability := range writeCapabilities {
		entries = append(entries, WindowsACLEntry{
			Action:     WindowsACLAllowWrite,
			Path:       capability.Root,
			Capability: capability.SID,
		})
		for _, path := range capability.ProtectedWriteDenyPaths {
			entries = append(entries, WindowsACLEntry{
				Action:     WindowsACLDenyWrite,
				Path:       path,
				Capability: capability.SID,
			})
		}
	}
	writeSIDs := windowsWriteCapabilitySIDs(writeCapabilities)
	for _, path := range config.PermissionProfile.FileSystem.DenyWrite {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		for _, sid := range writeSIDs {
			entries = append(entries, WindowsACLEntry{
				Action:     WindowsACLDenyWrite,
				Path:       path,
				Capability: sid,
			})
		}
	}
	readDenySIDs, err := windowsReadDenyCapabilitySIDs(config, writeSIDs)
	if err != nil {
		return WindowsACLPlan{}, err
	}
	for _, path := range planWindowsDenyReadPaths(config.PermissionProfile.FileSystem.DenyRead) {
		for _, sid := range readDenySIDs {
			entries = append(entries, WindowsACLEntry{
				Action:      WindowsACLDenyRead,
				Path:        path,
				Capability:  sid,
				Materialize: true,
			})
		}
	}

	// Deny write to shared Windows-writable directories (C:\, C:\ProgramData,
	// C:\Windows\Temp, C:\Users\Public) to prevent write-jail escape via the
	// added Users and Authenticated Users SIDs. Only the elevated tier
	// (WindowsSandboxLevelRestrictedToken, applied by `zero sandbox setup`
	// running as Administrator) reaches here with those SIDs on the token in
	// the first place — see createWindowsRestrictedTokenFromBase — and only
	// that tier has the WRITE_DAC needed to edit these system-owned DACLs.
	// The unelevated tier keeps the narrower (pre-widening) restricting-SID
	// set and never needs these entries.
	if config.SandboxLevel == WindowsSandboxLevelRestrictedToken {
		systemDrive := os.Getenv("SystemDrive")
		if systemDrive == "" {
			systemDrive = "C:"
		}
		systemRoot := os.Getenv("SystemRoot")
		if systemRoot == "" {
			systemRoot = systemDrive + `\Windows`
		}
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = systemDrive + `\ProgramData`
		}
		publicDir := os.Getenv("PUBLIC")
		if publicDir == "" {
			publicDir = systemDrive + `\Users\Public`
		}

		sharedDenyPaths := []string{
			systemDrive + `\`,
			programData,
			systemRoot + `\Temp`,
			publicDir,
		}

		caps, err := LoadOrCreateWindowsCapabilitySIDs(config.SandboxHome)
		if err != nil {
			return WindowsACLPlan{}, err
		}
		var allSIDs []string
		for _, cap := range writeCapabilities {
			allSIDs = append(allSIDs, cap.SID)
		}
		allSIDs = append(allSIDs, caps.ReadOnly)

		for _, denyPath := range sharedDenyPaths {
			if windowsPathEqualsAnyRoot(denyPath, writeCapabilities) {
				continue // Do not deny write if it is exactly an allowed write root
			}
			// Inheritance is intentionally left on: the write root's own
			// explicit Allow ACE (set directly on that path in its own group,
			// above) is a non-inherited entry, and canonical ACE ordering
			// always evaluates explicit entries before inherited ones — so an
			// inherited Deny from a shared ancestor here can never shadow it.
			// It also still defends newly created objects elsewhere under the
			// shared path: NTFS does not retroactively propagate an
			// inheritable ACE onto pre-existing children, which is exactly
			// why C:\Users\Public above is listed explicitly rather than
			// relied on via inheritance from C:\.
			for _, sid := range allSIDs {
				entries = append(entries, WindowsACLEntry{
					Action:     WindowsACLDenyWrite,
					Path:       denyPath,
					Capability: sid,
				})
			}
		}
	}

	return WindowsACLPlan{Entries: dedupeWindowsACLEntries(entries)}, nil
}

func windowsPathEqualsAnyRoot(path string, capabilities []windowsWriteRootCapability) bool {
	key := windowsCapabilityPathKey(path)
	if key == "" {
		return false
	}
	for _, cap := range capabilities {
		if windowsCapabilityPathKey(cap.Root) == key {
			return true
		}
	}
	return false
}

type windowsWriteRootCapability struct {
	Root                    string
	SID                     string
	ProtectedWriteDenyPaths []string
}

func windowsWriteRootCapabilities(config WindowsSandboxCommandConfig) ([]windowsWriteRootCapability, error) {
	out := make([]windowsWriteRootCapability, 0, len(config.PermissionProfile.FileSystem.WriteRoots))
	for _, root := range config.PermissionProfile.FileSystem.WriteRoots {
		rootPath := strings.TrimSpace(root.Root)
		if rootPath == "" {
			continue
		}
		sid, err := windowsCapabilitySIDForWriteRoot(config, rootPath)
		if err != nil {
			return nil, err
		}
		protected := make([]string, 0, len(root.ProtectedMetadataNames)+len(root.ReadOnlySubpaths))
		for _, subpath := range root.ReadOnlySubpaths {
			if trimmed := strings.TrimSpace(subpath); trimmed != "" {
				protected = append(protected, trimmed)
			}
		}
		for _, name := range root.ProtectedMetadataNames {
			if trimmed := strings.TrimSpace(name); trimmed != "" {
				protected = append(protected, filepath.Join(rootPath, trimmed))
			}
		}
		out = append(out, windowsWriteRootCapability{
			Root:                    rootPath,
			SID:                     sid,
			ProtectedWriteDenyPaths: protected,
		})
	}
	return out, nil
}

func windowsCapabilitySIDForWriteRoot(config WindowsSandboxCommandConfig, root string) (string, error) {
	if windowsRootMatchesWorkspace(root, config.WorkspaceRoots) {
		return WindowsWorkspaceCapabilitySID(config.SandboxHome, root)
	}
	return WindowsWritableRootCapabilitySID(config.SandboxHome, root)
}

func windowsWriteCapabilitySIDs(capabilities []windowsWriteRootCapability) []string {
	out := make([]string, 0, len(capabilities))
	seen := map[string]struct{}{}
	for _, capability := range capabilities {
		if capability.SID == "" {
			continue
		}
		if _, ok := seen[capability.SID]; ok {
			continue
		}
		seen[capability.SID] = struct{}{}
		out = append(out, capability.SID)
	}
	return out
}

func windowsReadDenyCapabilitySIDs(config WindowsSandboxCommandConfig, writeSIDs []string) ([]string, error) {
	if len(writeSIDs) > 0 {
		return writeSIDs, nil
	}
	if len(config.PermissionProfile.FileSystem.DenyRead) == 0 {
		return nil, nil
	}
	caps, err := LoadOrCreateWindowsCapabilitySIDs(config.SandboxHome)
	if err != nil {
		return nil, err
	}
	return []string{caps.ReadOnly}, nil
}

func planWindowsDenyReadPaths(paths []string) []string {
	out := make([]string, 0, len(paths)*2)
	seen := map[string]struct{}{}
	push := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		key := windowsCapabilityPathKey(path)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, path)
	}
	for _, path := range paths {
		push(path)
		if resolved, err := filepath.EvalSymlinks(path); err == nil {
			push(resolved)
		}
	}
	return out
}

func dedupeWindowsACLEntries(entries []WindowsACLEntry) []WindowsACLEntry {
	out := make([]WindowsACLEntry, 0, len(entries))
	seen := map[string]struct{}{}
	for _, entry := range entries {
		if entry.Action == "" || strings.TrimSpace(entry.Path) == "" || strings.TrimSpace(entry.Capability) == "" {
			continue
		}
		key := string(entry.Action) + "\x00" + windowsCapabilityPathKey(entry.Path) + "\x00" + strings.ToLower(entry.Capability)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, entry)
	}
	return out
}
