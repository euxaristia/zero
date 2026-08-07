//go:build !windows

package kimiidentity

import (
	"errors"
	"syscall"
)

// processAlive reports whether pid is a live process on POSIX. Signal 0 does
// not deliver a signal; it only checks existence/permission. ESRCH means no
// such process (dead); EPERM means it exists but we may not signal it (alive).
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true
	}
	return errors.Is(err, syscall.EPERM)
}
