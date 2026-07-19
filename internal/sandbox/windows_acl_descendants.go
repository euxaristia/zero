package sandbox

import "strings"

// Shared basename policies and pure helpers for the Windows descendant-scan
// fail-closed rules. The Win32 walk lives in windows_acl_descendants_windows.go;
// these helpers are compiled on every GOOS so non-Windows tests can pin the
// policy without the Windows APIs.

// windowsDescendantScanSystemLockedNames are basenames that Windows keeps
// exclusive to SYSTEM (or otherwise unreadable even to elevated Administrators
// without taking ownership). They appear under every fixed volume root. Listing
// or DACL-reading them fails on healthy machines; treating that as incomplete
// coverage would make DenyRead setup fail everywhere. They never grant
// BUILTIN\Users / Authenticated Users write in stock configuration.
var windowsDescendantScanSystemLockedNames = map[string]struct{}{
	"system volume information": {},
	"$recycle.bin":              {},
	"recovery":                  {},
}

// windowsDescendantScanPruneNames are basenames of large stock trees that are
// not Users/AuthUsers-writable at their root on a normal install. When the
// write probe agrees they are not writable, the scan does not descend into
// them. This is the only reason a full C:\ walk stays within the entry budget
// without silently skipping arbitrary user-created trees.
var windowsDescendantScanPruneNames = map[string]struct{}{
	"windows":                {},
	"program files":          {},
	"program files (x86)":    {},
	"perflogs":               {},
	"documents and settings": {},
	// ProgramData and Users\Public are themselves shared deny roots and are
	// scanned as separate roots by applyWindowsACLPlan. Pruning them under C:\
	// avoids double-walking and double-stamping the same descendants.
	"programdata": {},
	"users":       {},
}

func windowsDescendantScanNameIsSystemLocked(name string) bool {
	_, ok := windowsDescendantScanSystemLockedNames[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

func windowsDescendantScanNameIsPruned(name string) bool {
	_, ok := windowsDescendantScanPruneNames[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

// windowsMountPathIsOnlySystemDrive reports whether a volume mount path is the
// system drive root (e.g. `C:\` or `C:`) rather than another letter or a
// folder mount such as `C:\mnt\data`. Used by the volume gate so a second
// fixed volume mounted only as a folder is rejected the same as one mounted
// on a drive letter.
func windowsMountPathIsOnlySystemDrive(mountPath, systemDrive string) bool {
	trimmed := strings.TrimSuffix(mountPath, `\`)
	return strings.EqualFold(strings.ToUpper(trimmed), strings.ToUpper(systemDrive))
}
