package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildWindowsACLPlanForWorkspaceWriteProfile(t *testing.T) {
	home := t.TempDir()
	config := WindowsSandboxCommandConfig{
		SandboxHome:    home,
		WorkspaceRoots: []string{`C:\workspace`},
		SandboxLevel:   WindowsSandboxLevelRestrictedToken,
		PermissionProfile: PermissionProfile{
			FileSystem: FileSystemPolicy{
				Kind: FileSystemRestricted,
				WriteRoots: []WritableRoot{
					{
						Root:                   `C:\workspace`,
						ReadOnlySubpaths:       []string{`C:\workspace\vendor`},
						ProtectedMetadataNames: []string{".git", ".zero"},
					},
					{Root: `D:\cache`},
				},
				DenyRead:  []string{`C:\workspace\secret-read`},
				DenyWrite: []string{`C:\workspace\secret-write`},
			},
			Network: NetworkPolicy{Mode: NetworkDeny},
		},
	}

	plan, err := BuildWindowsACLPlan(config)
	if err != nil {
		t.Fatalf("BuildWindowsACLPlan: %v", err)
	}
	workspaceSID, err := WindowsWorkspaceCapabilitySID(home, `c:/workspace`)
	if err != nil {
		t.Fatalf("WindowsWorkspaceCapabilitySID: %v", err)
	}
	cacheSID, err := WindowsWritableRootCapabilitySID(home, `d:/cache`)
	if err != nil {
		t.Fatalf("WindowsWritableRootCapabilitySID: %v", err)
	}

	assertWindowsACLEntry(t, plan, WindowsACLAllowWrite, `C:\workspace`, workspaceSID, false)
	assertWindowsACLEntry(t, plan, WindowsACLAllowWrite, `D:\cache`, cacheSID, false)
	assertWindowsACLEntry(t, plan, WindowsACLDenyWrite, `C:\workspace\vendor`, workspaceSID, false)
	assertWindowsACLEntry(t, plan, WindowsACLDenyWrite, `C:\workspace\.git`, workspaceSID, false)
	assertWindowsACLEntry(t, plan, WindowsACLDenyWrite, `C:\workspace\.zero`, workspaceSID, false)
	assertWindowsACLEntry(t, plan, WindowsACLDenyWrite, `C:\workspace\secret-write`, workspaceSID, false)
	assertWindowsACLEntry(t, plan, WindowsACLDenyWrite, `C:\workspace\secret-write`, cacheSID, false)
	assertWindowsACLEntry(t, plan, WindowsACLDenyRead, `C:\workspace\secret-read`, workspaceSID, true)
	assertWindowsACLEntry(t, plan, WindowsACLDenyRead, `C:\workspace\secret-read`, cacheSID, true)

	caps, err := LoadOrCreateWindowsCapabilitySIDs(home)
	if err != nil {
		t.Fatalf("LoadOrCreateWindowsCapabilitySIDs: %v", err)
	}
	systemDrive, systemRoot, programData, publicDir := windowsSharedDenyPathsForTest(t)

	for _, sid := range []string{workspaceSID, cacheSID, caps.ReadOnly} {
		assertWindowsACLEntryInheritance(t, plan, WindowsACLDenyWrite, systemDrive+`\`, sid, false, true)
		assertWindowsACLEntryInheritance(t, plan, WindowsACLDenyWrite, programData, sid, false, true)
		assertWindowsACLEntryInheritance(t, plan, WindowsACLDenyWrite, systemRoot+`\Temp`, sid, false, true)
		assertWindowsACLEntryInheritance(t, plan, WindowsACLDenyWrite, publicDir, sid, false, true)
	}
}

// TestBuildWindowsACLPlanOmitsSharedDenyPathsWhenUnelevated pins the fix for
// the unelevated tier aborting every sandboxed command: BuildWindowsACLPlan
// must not add DenyWrite entries for C:\, C:\ProgramData, C:\Windows\Temp, or
// C:\Users\Public when SandboxLevel is WindowsSandboxLevelUnelevated, because
// SetNamedSecurityInfo on those system-owned paths requires WRITE_DAC that an
// ordinary (non-Administrator) user does not have. The unelevated tier never
// puts the Users/Authenticated Users SIDs on the token in the first place
// (see createWindowsRestrictedTokenFromBase), so it does not need these
// mitigating entries.
func TestBuildWindowsACLPlanOmitsSharedDenyPathsWhenUnelevated(t *testing.T) {
	home := t.TempDir()
	plan, err := BuildWindowsACLPlan(WindowsSandboxCommandConfig{
		SandboxHome:    home,
		WorkspaceRoots: []string{`C:\workspace`},
		SandboxLevel:   WindowsSandboxLevelUnelevated,
		PermissionProfile: PermissionProfile{
			FileSystem: FileSystemPolicy{
				Kind:       FileSystemRestricted,
				WriteRoots: []WritableRoot{{Root: `C:\workspace`}},
			},
			Network: NetworkPolicy{Mode: NetworkDeny},
		},
	})
	if err != nil {
		t.Fatalf("BuildWindowsACLPlan: %v", err)
	}
	systemDrive, systemRoot, programData, publicDir := windowsSharedDenyPathsForTest(t)
	for _, path := range []string{systemDrive + `\`, programData, systemRoot + `\Temp`, publicDir} {
		for _, entry := range plan.Entries {
			if entry.Action == WindowsACLDenyWrite && windowsCapabilityPathKey(entry.Path) == windowsCapabilityPathKey(path) {
				t.Fatalf("unelevated ACL plan = %#v, want no DenyWrite entry for shared path %q", plan.Entries, path)
			}
		}
	}
}

// windowsSharedDenyPathsForTest calls the same trusted-path resolution
// BuildWindowsACLPlan itself uses, rather than reimplementing the
// resolution logic independently, so this test cannot silently drift out of
// sync with (or mask a regression in) the production resolver.
func windowsSharedDenyPathsForTest(t *testing.T) (systemDrive, systemRoot, programData, publicDir string) {
	t.Helper()
	systemDrive, systemRoot, programData, publicDir, err := resolveWindowsSharedDenyPaths()
	if err != nil {
		t.Fatalf("resolveWindowsSharedDenyPaths: %v", err)
	}
	return systemDrive, systemRoot, programData, publicDir
}

func TestBuildWindowsACLPlanUsesReadOnlySIDWithoutWriteRoots(t *testing.T) {
	home := t.TempDir()
	caps, err := LoadOrCreateWindowsCapabilitySIDs(home)
	if err != nil {
		t.Fatalf("LoadOrCreateWindowsCapabilitySIDs: %v", err)
	}
	plan, err := BuildWindowsACLPlan(WindowsSandboxCommandConfig{
		SandboxHome:  home,
		SandboxLevel: WindowsSandboxLevelRestrictedToken,
		PermissionProfile: PermissionProfile{
			FileSystem: FileSystemPolicy{
				Kind:     FileSystemRestricted,
				DenyRead: []string{`C:\workspace\secret-read`},
			},
			Network: NetworkPolicy{Mode: NetworkDeny},
		},
	})
	if err != nil {
		t.Fatalf("BuildWindowsACLPlan: %v", err)
	}
	if len(plan.Entries) != 5 {
		t.Fatalf("ACL entries = %#v, want five entries (1 deny-read, 4 deny-write)", plan.Entries)
	}
	assertWindowsACLEntry(t, plan, WindowsACLDenyRead, `C:\workspace\secret-read`, caps.ReadOnly, true)
	systemDrive, systemRoot, programData, publicDir := windowsSharedDenyPathsForTest(t)
	assertWindowsACLEntryInheritance(t, plan, WindowsACLDenyWrite, systemDrive+`\`, caps.ReadOnly, false, true)
	assertWindowsACLEntryInheritance(t, plan, WindowsACLDenyWrite, programData, caps.ReadOnly, false, true)
	assertWindowsACLEntryInheritance(t, plan, WindowsACLDenyWrite, systemRoot+`\Temp`, caps.ReadOnly, false, true)
	assertWindowsACLEntryInheritance(t, plan, WindowsACLDenyWrite, publicDir, caps.ReadOnly, false, true)
}

func TestBuildWindowsACLPlanRejectsUnrestrictedProfiles(t *testing.T) {
	_, err := BuildWindowsACLPlan(WindowsSandboxCommandConfig{
		SandboxHome: t.TempDir(),
		PermissionProfile: PermissionProfile{
			FileSystem: FileSystemPolicy{Kind: FileSystemUnrestricted},
			Network:    NetworkPolicy{Mode: NetworkAllow},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "restricted filesystem") {
		t.Fatalf("BuildWindowsACLPlan error = %v, want restricted filesystem error", err)
	}
}

func TestPlanWindowsDenyReadPathsIncludesCanonicalExistingPath(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	wantRealDir, err := filepath.EvalSymlinks(realDir)
	if err != nil {
		t.Fatalf("EvalSymlinks real dir: %v", err)
	}
	linkDir := filepath.Join(root, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	paths := planWindowsDenyReadPaths([]string{linkDir})
	if !windowsPathListContains(paths, linkDir) {
		t.Fatalf("deny-read paths = %#v, want lexical path %q", paths, linkDir)
	}
	if !windowsPathListContains(paths, wantRealDir) {
		t.Fatalf("deny-read paths = %#v, want canonical path %q", paths, wantRealDir)
	}
}

func assertWindowsACLEntry(t *testing.T, plan WindowsACLPlan, action WindowsACLAction, path string, capability string, materialize bool) {
	t.Helper()
	assertWindowsACLEntryInheritance(t, plan, action, path, capability, materialize, false)
}

func assertWindowsACLEntryInheritance(t *testing.T, plan WindowsACLPlan, action WindowsACLAction, path string, capability string, materialize bool, noInherit bool) {
	t.Helper()
	for _, entry := range plan.Entries {
		if entry.Action == action &&
			windowsCapabilityPathKey(entry.Path) == windowsCapabilityPathKey(path) &&
			strings.EqualFold(entry.Capability, capability) &&
			entry.Materialize == materialize &&
			entry.NoInherit == noInherit {
			return
		}
	}
	t.Fatalf("ACL entries = %#v, want %s %q capability %q materialize=%v noInherit=%v", plan.Entries, action, path, capability, materialize, noInherit)
}

func windowsPathListContains(paths []string, want string) bool {
	wantKey := windowsCapabilityPathKey(want)
	for _, path := range paths {
		if windowsCapabilityPathKey(path) == wantKey {
			return true
		}
	}
	return false
}
