package sandbox

import "testing"

func TestWindowsDescendantScanNamePolicies(t *testing.T) {
	for _, name := range []string{
		"System Volume Information",
		"SYSTEM VOLUME INFORMATION",
		"$Recycle.Bin",
		"Recovery",
	} {
		if !windowsDescendantScanNameIsSystemLocked(name) {
			t.Fatalf("windowsDescendantScanNameIsSystemLocked(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"ProgramData", "plain", "Users"} {
		if windowsDescendantScanNameIsSystemLocked(name) {
			t.Fatalf("windowsDescendantScanNameIsSystemLocked(%q) = true, want false", name)
		}
	}

	for _, name := range []string{
		"Windows",
		"Program Files",
		"Program Files (x86)",
		"ProgramData",
		"Users",
		"PerfLogs",
	} {
		if !windowsDescendantScanNameIsPruned(name) {
			t.Fatalf("windowsDescendantScanNameIsPruned(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"AppData", "zero-project", "Temp"} {
		if windowsDescendantScanNameIsPruned(name) {
			t.Fatalf("windowsDescendantScanNameIsPruned(%q) = true, want false", name)
		}
	}
}

func TestWindowsMountPathIsOnlySystemDrive(t *testing.T) {
	cases := []struct {
		mount, system string
		want          bool
	}{
		{`C:\`, `C:`, true},
		{`C:`, `C:`, true},
		{`c:\`, `C:`, true},
		{`D:\`, `C:`, false},
		{`C:\mnt\data`, `C:`, false},
		{`C:\mnt\data\`, `C:`, false},
		{`\\?\Volume{guid}\`, `C:`, false},
	}
	for _, tc := range cases {
		got := windowsMountPathIsOnlySystemDrive(tc.mount, tc.system)
		if got != tc.want {
			t.Fatalf("windowsMountPathIsOnlySystemDrive(%q, %q) = %v, want %v", tc.mount, tc.system, got, tc.want)
		}
	}
}
