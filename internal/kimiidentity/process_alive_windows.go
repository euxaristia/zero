//go:build windows

package kimiidentity

import (
	"errors"

	"golang.org/x/sys/windows"
)

// processAlive reports whether pid is a live process on Windows. It opens the
// process for limited query access; a successful open with a non-exited status
// means the PID is live. x/sys is already a module dependency.
//
// Fail closed on inconclusive results: only a proven-dead process makes a
// repair lease reclaimable. Access-denied means the process exists but we
// cannot open it (alive). ERROR_INVALID_PARAMETER is the usual free/invalid
// PID signal (dead). Any other OpenProcess failure, and GetExitCodeProcess
// failure after a successful open, are treated as alive.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		// Access denied: process exists under a tighter ACL (or higher
		// integrity). Do not reclaim its repair lock.
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return true
		}
		// Free/invalid PID typically returns ERROR_INVALID_PARAMETER.
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return false
		}
		// Unknown open failure: fail closed (do not reclaim).
		return true
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
