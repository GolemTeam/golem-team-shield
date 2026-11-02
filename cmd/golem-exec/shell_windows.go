package main

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// realShell is Git for Windows' bash (or sh), which is what Claude Code runs
// its Bash tool with on Windows. The machine-wide install is preferred: its
// registry key and directory are writable only by an administrator.
func realShell(invoked string) string {
	name := "bash.exe"
	if lower := strings.ToLower(invoked); !strings.Contains(lower, "bash") && strings.Contains(lower, "sh") {
		name = "sh.exe"
	}
	for _, root := range gitRoots() {
		p := filepath.Join(root, "bin", name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
	}
	return filepath.Join(`C:\Program Files\Git\bin`, name)
}

func gitRoots() []string {
	var roots []string
	for _, hive := range []registry.Key{registry.LOCAL_MACHINE, registry.CURRENT_USER} {
		k, err := registry.OpenKey(hive, `SOFTWARE\GitForWindows`, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		if v, _, err := k.GetStringValue("InstallPath"); err == nil && filepath.IsAbs(v) {
			roots = append(roots, v)
		}
		k.Close()
	}
	roots = append(roots, `C:\Program Files\Git`)
	if local := os.Getenv("LOCALAPPDATA"); filepath.IsAbs(local) {
		roots = append(roots, filepath.Join(local, "Programs", "Git"))
	}
	return roots
}
