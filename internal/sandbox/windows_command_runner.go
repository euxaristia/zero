package sandbox

import (
	"fmt"
	"io"
	"strings"
)

func RunWindowsSandboxCommandRunner(args []string, stderr io.Writer) int {
	config, err := ParseWindowsSandboxCommandArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, WindowsSandboxCommandRunnerName+": "+err.Error())
		return 2
	}
	if _, err := LoadOrCreateWindowsCapabilitySIDs(config.SandboxHome); err != nil {
		fmt.Fprintln(stderr, WindowsSandboxCommandRunnerName+": "+err.Error())
		return 1
	}
	return runWindowsSandboxCommand(config, stderr)
}

// windowsDenyReadRestrictedTokenUnsupported reports that elevated restricted-
// token sandboxing cannot run profiles with DenyRead until access-time
// confinement exists. A fully restricted token without Users/AuthUsers cannot
// load ordinary system executables; adding those groups reopens write grants
// outside WriteRoots. Prefer a clear rejection over a silent launch failure.
func windowsDenyReadRestrictedTokenUnsupported(config WindowsSandboxCommandConfig) error {
	if config.SandboxLevel != WindowsSandboxLevelRestrictedToken {
		return nil
	}
	if len(config.PermissionProfile.FileSystem.DenyRead) == 0 {
		return nil
	}
	return fmt.Errorf(
		"DenyRead is not supported with the elevated Windows restricted-token sandbox: "+
			"without Users/Authenticated Users in the restricting SID set, ordinary system "+
			"binaries under Program Files and Windows cannot load, and adding those groups "+
			"would admit their existing write grants outside WriteRoots. "+
			"Use `--sandbox forbid`, the unelevated sandbox tier, omit DenyRead, or wait for "+
			"access-time confinement (AppContainer/LPAC-style). Configured DenyRead paths: %s",
		strings.Join(config.PermissionProfile.FileSystem.DenyRead, ", "),
	)
}
