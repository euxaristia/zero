//go:build windows

package kimiidentity

import (
	"errors"
	"os"
	"os/exec"
	"testing"
)

// TestProcessAliveExitCode259IsDead is the regression for treating STILL_ACTIVE
// (259) as a process exit code rather than a liveness flag. A dead child that
// exits with 259 must be reported as not alive so a stale repair lease can be
// reclaimed.
func TestProcessAliveExitCode259IsDead(t *testing.T) {
	cmd := exec.Command("cmd", "/C", "exit /b 259")
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	pid := cmd.Process.Pid
	err := cmd.Wait()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 259 {
		t.Fatalf("Wait: %v (want ExitError with code 259)", err)
	}
	// Keep a live reference so the process object is still openable by PID
	// while we probe (Go retains a handle until Process is released).
	_ = cmd.Process
	if processAlive(pid) {
		t.Fatalf("processAlive(%d) = true after exit code 259; want false (dead)", pid)
	}
}

func TestProcessAliveSelfIsLive(t *testing.T) {
	if !processAlive(os.Getpid()) {
		t.Fatal("processAlive(self) = false; want true")
	}
}

func TestProcessAliveNonPositiveIsDead(t *testing.T) {
	if processAlive(0) {
		t.Fatal("processAlive(0) = true; want false")
	}
	if processAlive(-1) {
		t.Fatal("processAlive(-1) = true; want false")
	}
}
