//go:build windows

package worktrees

import "golang.org/x/sys/windows"

// osProcessAlive reports whether pid is a live process on Windows. It opens
// the process for limited query access; a successful open with a
// non-exited status means the PID is live. OpenProcess succeeding is not
// enough on its own: a handle can remain valid briefly after the process it
// named has exited, so GetExitCodeProcess must confirm STILL_ACTIVE before
// treating the PID as live.
func osProcessAlive(pid int) bool {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	var code uint32
	if err := windows.GetExitCodeProcess(handle, &code); err != nil {
		// Could not query; treat the open as proof of life (conservative: do
		// not reclaim a lock we are unsure about).
		return true
	}
	const stillActive = 259 // STILL_ACTIVE
	return code == stillActive
}
