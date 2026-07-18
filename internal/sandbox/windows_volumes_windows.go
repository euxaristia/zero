//go:build windows

package sandbox

import (
	"strings"

	"golang.org/x/sys/windows"
)

// windowsSystemDriveIsOnlyFixedVolume reports whether the system drive is
// this machine's only fixed volume.
//
// The compensating shared-directory DenyWrite mitigation covers exactly four
// paths, all on the system drive, while the broadened Users/Authenticated
// Users restricting SIDs participate in every access check on every volume.
// A stock non-system NTFS data volume grants Authenticated Users Modify at
// its root with (OI)(CI)(IO) inheritance, so on a multi-volume host a
// broadened token could write anywhere on such a volume, outside every
// configured write root — and no bounded descendant scan can patch a grant
// inherited volume-wide. The broadening is therefore only sound when there
// is no other fixed volume to protect.
//
// Fail closed: an enumeration failure, an unresolvable system drive, or any
// additional fixed volume all report false, keeping the narrow restricting-
// SID set (reads of Users-granted system paths stay broken on such hosts,
// but the write jail holds).
func windowsSystemDriveIsOnlyFixedVolume() bool {
	windowsDir, err := windows.GetSystemWindowsDirectory()
	if err != nil || len(windowsDir) < 2 {
		return false
	}
	systemDrive := strings.ToUpper(windowsDir[:2]) // e.g. "C:"

	buf := make([]uint16, 1024)
	n, err := windows.GetLogicalDriveStrings(uint32(len(buf)), &buf[0])
	if err != nil || n == 0 || int(n) > len(buf) {
		return false
	}
	for _, root := range windowsSplitNulList(buf[:n]) {
		rootPtr, err := windows.UTF16PtrFromString(root)
		if err != nil {
			return false
		}
		if windows.GetDriveType(rootPtr) != windows.DRIVE_FIXED {
			continue
		}
		if !strings.EqualFold(strings.ToUpper(strings.TrimSuffix(root, `\`)), systemDrive) {
			return false
		}
	}
	return true
}

// windowsSplitNulList splits the double-NUL-terminated UTF-16 string list
// returned by GetLogicalDriveStrings into Go strings.
func windowsSplitNulList(buf []uint16) []string {
	var out []string
	start := 0
	for i, c := range buf {
		if c == 0 {
			if i > start {
				out = append(out, windows.UTF16ToString(buf[start:i]))
			}
			start = i + 1
		}
	}
	if start < len(buf) {
		if s := windows.UTF16ToString(buf[start:]); s != "" {
			out = append(out, s)
		}
	}
	return out
}
