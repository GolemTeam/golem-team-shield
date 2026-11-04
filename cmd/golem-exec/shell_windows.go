package main

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// realShell is Git for Windows' bash (or sh), which is what Claude Code runs
// its Bash tool with on Windows, or PowerShell when the shim answers as
// pwsh.exe or powershell.exe for an agent's hook. Each comes from where only
// an administrator can write, never from PATH: the jail is only as good as
// the binary it wraps.
func realShell(invoked string) string {
	switch strings.TrimSuffix(strings.ToLower(filepath.Base(invoked)), ".exe") {
	case "pwsh":
		return realPwsh()
	case "powershell":
		return windowsPowerShell()
	}
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

// realPwsh is PowerShell 7's machine-wide install, from the registry key its
// installer writes, or its default directory.
func realPwsh() string {
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\PowerShellCore\InstalledVersions`, registry.ENUMERATE_SUB_KEYS); err == nil {
		names, _ := k.ReadSubKeyNames(-1)
		k.Close()
		for _, n := range names {
			v, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\PowerShellCore\InstalledVersions\`+n, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			loc, _, err := v.GetStringValue("InstallLocation")
			v.Close()
			if p := filepath.Join(loc, "pwsh.exe"); err == nil && filepath.IsAbs(loc) && isFile(p) {
				return p
			}
		}
	}
	if p := filepath.Join(`C:\Program Files\PowerShell\7`, "pwsh.exe"); isFile(p) {
		return p
	}
	return windowsPowerShell()
}

// windowsPowerShell is the PowerShell 5.1 every Windows has, in System32.
func windowsPowerShell() string {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		sys = `C:\Windows\System32`
	}
	return filepath.Join(sys, "WindowsPowerShell", "v1.0", "powershell.exe")
}

func isFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}
