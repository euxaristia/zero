package sandbox

import (
	"strings"
	"testing"
)

func TestWindowsDenyReadRestrictedTokenUnsupported(t *testing.T) {
	// Restricted-token + DenyRead must be rejected before launch.
	err := windowsDenyReadRestrictedTokenUnsupported(WindowsSandboxCommandConfig{
		SandboxLevel: WindowsSandboxLevelRestrictedToken,
		PermissionProfile: PermissionProfile{
			FileSystem: FileSystemPolicy{
				Kind:     FileSystemRestricted,
				DenyRead: []string{`C:\secret`, `D:\private`},
			},
		},
	})
	if err == nil {
		t.Fatal("expected unsupported error for restricted-token DenyRead profile")
	}
	msg := err.Error()
	for _, want := range []string{"DenyRead", "not supported", "restricted-token", `C:\secret`} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q missing %q", msg, want)
		}
	}

	// No DenyRead: allowed (WRITE_RESTRICTED path can launch system tools).
	if err := windowsDenyReadRestrictedTokenUnsupported(WindowsSandboxCommandConfig{
		SandboxLevel: WindowsSandboxLevelRestrictedToken,
		PermissionProfile: PermissionProfile{
			FileSystem: FileSystemPolicy{Kind: FileSystemRestricted},
		},
	}); err != nil {
		t.Fatalf("unexpected error without DenyRead: %v", err)
	}

	// Unelevated + DenyRead remains allowed (different token tier).
	if err := windowsDenyReadRestrictedTokenUnsupported(WindowsSandboxCommandConfig{
		SandboxLevel: WindowsSandboxLevelUnelevated,
		PermissionProfile: PermissionProfile{
			FileSystem: FileSystemPolicy{
				Kind:     FileSystemRestricted,
				DenyRead: []string{`C:\secret`},
			},
		},
	}); err != nil {
		t.Fatalf("unexpected error for unelevated DenyRead: %v", err)
	}
}
