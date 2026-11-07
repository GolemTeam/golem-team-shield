package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/GolemTeam/golem-team-shield/internal/jsonobject"
	"github.com/GolemTeam/golem-team-shield/shield"
)

// Run by its own name, golem-exec sets itself up as Claude Code's shell on a
// machine with no Golem agent, and never acts as a shell. Run under a shell's
// name (golem-zsh, golem-bash, bash, sh, bash.exe) it is the shim.

const cliUsage = `usage: golem-exec <command>

  install [--strict]   jail the shell commands Claude Code, Codex, Gemini CLI, Cursor and Copilot CLI run
  install --all-agents also jail the agents whose own approval would see only the jail
                       (Codex, Gemini CLI and Copilot CLI on Windows, and Devin): "jail_past_approval"
  install --refresh    update an installed shim to this binary, and nothing else
  status               show what is installed and the policy commands get
  firewall install     on Windows, as administrator: hold an allowed-hosts network to its list
  firewall remove      take the shield's firewall filters out again
  apparmor install     on Ubuntu, as root: let the jail make the network namespace an allowed-hosts list needs
  apparmor remove      take golem-exec's AppArmor profile and its copy out again
  test                 check that the jail blocks what it should
  uninstall [--purge]  put the agents' shells back (--purge also removes ~/.golem/shield.json)
  version              print the version

Settings: ~/.golem/shield.json. A new install keeps writes to the project, temp
and tool caches ("writes": "workspace"); --strict also keeps cloud credentials
out of reach.
`

func isSelf(invoked string) bool {
	name := strings.TrimSuffix(strings.ToLower(invoked), ".exe")
	return name == "golem-exec"
}

// setup is everything the commands touch, so tests can point it elsewhere.
type setup struct {
	home       string
	goos       string
	exe        string
	loginShell string
	codexHome  string
	witness    string
	stdin      io.Reader
	stdout     io.Writer
	stderr     io.Writer
	canJail    func() bool
	firewallOn func() (bool, error)
	namespaces func(self string) shield.Namespaces
	agentRuns  func() bool
	selfTest   func(shim, command string) (int, error)
}

func newSetup(witness string) *setup {
	home, _ := os.UserHomeDir()
	exe, _ := os.Executable()
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	s := &setup{
		home: home, goos: runtime.GOOS, exe: exe, loginShell: os.Getenv("SHELL"), codexHome: os.Getenv("CODEX_HOME"), witness: witness,
		stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, canJail: canJail, firewallOn: firewallInstalled, namespaces: shield.LinuxNamespaces, selfTest: runThroughShim,
	}
	s.agentRuns = s.agentPresent
	return s
}

func runCommand(s *setup, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(s.stderr, cliUsage)
		return 2
	}
	flags := map[string]bool{}
	for _, a := range args[1:] {
		flags[strings.TrimLeft(a, "-")] = true
	}
	switch args[0] {
	case "install":
		if flags["refresh"] {
			return s.refresh()
		}
		return s.install(flags["strict"], flags["all-agents"])
	case "uninstall":
		return s.uninstall(flags["purge"])
	case "status":
		return s.status()
	case "hook":
		return s.hook(args[1:])
	case "firewall":
		return s.firewall(args[1:])
	case "apparmor":
		return s.apparmor(args[1:])
	case "test":
		return s.test()
	case "help", "-h", "--help":
		fmt.Fprint(s.stdout, cliUsage)
		return 0
	case "version", "--version":
		fmt.Fprintln(s.stdout, "golem-exec "+version)
		return 0
	}
	fmt.Fprintf(s.stderr, "golem-exec: unknown command %q\n\n%s", args[0], cliUsage)
	return 2
}

func (s *setup) binDir() string       { return filepath.Join(s.home, ".golem", "bin") }
func (s *setup) settingsPath() string { return filepath.Join(s.home, ".claude", "settings.json") }

// shims are the names golem-exec answers to as a shell, the first being the
// one Claude Code is pointed at.
func (s *setup) shims() []string {
	if s.goos == "windows" {
		return []string{filepath.Join(s.binDir(), "bash.exe")}
	}
	zsh, bash := filepath.Join(s.binDir(), "golem-zsh"), filepath.Join(s.binDir(), "golem-bash")
	if strings.Contains(filepath.Base(s.loginShell), "bash") {
		return []string{bash, zsh}
	}
	return []string{zsh, bash}
}

func (s *setup) claudeShell() shield.ClaudeShell {
	return shield.ClaudeShell{
		Windows: s.goos == "windows",
		Shim:    s.shims()[0],
		Ours: func(p string) bool {
			if s.goos == "windows" {
				return strings.EqualFold(filepath.Clean(p), s.shims()[0])
			}
			return strings.HasPrefix(p, s.binDir()+string(filepath.Separator)+"golem-")
		},
		Ready: func(p string) bool {
			fi, err := os.Stat(p)
			return err == nil && fi.Mode().IsRegular() && (s.goos == "windows" || fi.Mode()&0o111 != 0)
		},
	}
}

// agentPresent: a machine that joined Golem, or whose agent answers, has its
// shield set up and decided by the agent.
func (s *setup) agentPresent() bool {
	if _, err := os.Stat(filepath.Join(s.home, ".golem", "joined")); err == nil {
		return true
	}
	c := &http.Client{Timeout: 500 * time.Millisecond}
	resp, err := c.Get(strings.TrimRight(s.witness, "/") + "/healthz")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

const agentManages = "The Golem agent runs the shield on this machine and decides its policy.\n" +
	"Its settings are in the console, or `golem lockdown` with no account. Check it with `golem doctor`.\n"

func (s *setup) install(strict, allAgents bool) int {
	if s.agentRuns() {
		fmt.Fprint(s.stdout, agentManages)
		return 0
	}
	if !s.canJail() {
		fmt.Fprintln(s.stderr, "golem-exec: this machine cannot build the jail:", jailUnavailable(s.goos))
		return 1
	}
	if err := s.installShims(); err != nil {
		fmt.Fprintf(s.stderr, "golem-exec: could not install into %s: %v\n", s.binDir(), err)
		return 1
	}
	fmt.Fprintf(s.stdout, "Installed the shim in %s\n", s.binDir())

	cfgPath := shield.ConfigPath(s.home)
	if _, found, err := shield.LoadConfig(cfgPath); !found {
		cfg := shield.DefaultConfig()
		if strict {
			cfg = shield.StrictConfig()
		}
		if err := shield.WriteConfig(cfgPath, cfg); err != nil {
			fmt.Fprintf(s.stderr, "golem-exec: could not write %s: %v\n", cfgPath, err)
			return 1
		}
		fmt.Fprintf(s.stdout, "Wrote the settings to %s\n", cfgPath)
	} else if err != nil {
		fmt.Fprintf(s.stderr, "golem-exec: %s is not valid (%v); every command is locked down until it is fixed\n", cfgPath, err)
	} else if strict {
		fmt.Fprintf(s.stdout, "Kept your settings in %s; set \"cloud_credentials\": false there for --strict\n", cfgPath)
	}
	if allAgents {
		if err := s.jailPastApproval(cfgPath); err != nil {
			fmt.Fprintf(s.stderr, "golem-exec: could not set \"jail_past_approval\" in %s: %v\n", cfgPath, err)
			return 1
		}
	}

	code := 0
	cs := s.claudeShell()
	if changes, err := s.editSettings(cs.Wire); err != nil {
		fmt.Fprintf(s.stderr, "golem-exec: could not edit %s (%v). Add this to it yourself:\n  \"env\": {\"%s\": %q}\n", s.settingsPath(), err, cs.Var(), cs.Shim)
		code = 1
	} else if len(changes) > 0 {
		for _, c := range changes {
			fmt.Fprintf(s.stdout, "Claude Code: %s\n", c)
		}
	} else if current := s.currentShell(cs); current != "" && !cs.Ours(current) {
		fmt.Fprintf(s.stdout, "Claude Code's shell is set to %s, so it was left alone. To jail it, set %s to %s in %s.\n",
			current, cs.Var(), cs.Shim, s.settingsPath())
	}

	if s.wireAgents(false) != 0 {
		code = 1
	}

	if s.test() != 0 {
		code = 1
	}
	fmt.Fprintln(s.stdout)
	fmt.Fprintln(s.stdout, "Restart your agents so they run their shell commands in the jail.")
	fmt.Fprintln(s.stdout, "  settings:  "+cfgPath)
	fmt.Fprintln(s.stdout, "  check:     golem-exec status")
	fmt.Fprintln(s.stdout, "  remove:    golem-exec uninstall")
	return code
}

// jailPastApproval sets jail_past_approval in the settings, leaving the rest
// of the file as the person wrote it.
func (s *setup) jailPastApproval(cfgPath string) error {
	if c, _, err := shield.LoadConfig(cfgPath); err != nil || c.JailPastApproval {
		return err
	}
	doc, _, err := jsonobject.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	doc.Set("jail_past_approval", json.RawMessage("true"))
	if err := jsonobject.WriteFile(cfgPath, doc); err != nil {
		return err
	}
	fmt.Fprintln(s.stdout, "Agents whose own approval would see only the jail are jailed too: one \"always allow\" in them could approve every later command")
	return nil
}

// refresh replaces an installed shim with this binary, so upgrading the copy a
// package manager keeps also upgrades the one Claude Code runs. It touches
// nothing else, does nothing where the agent manages the shield or nothing is
// installed, and never fails: a package manager runs it after every upgrade.
func (s *setup) refresh() int {
	if s.agentRuns() {
		return 0
	}
	installed := filepath.Join(s.binDir(), "golem-exec")
	if s.goos == "windows" {
		installed = s.shims()[0]
	}
	if _, err := os.Stat(installed); err != nil {
		return 0
	}
	if err := s.installShims(); err != nil {
		fmt.Fprintf(s.stderr, "golem-exec: could not update the shim in %s (%v); run golem-exec install\n", s.binDir(), err)
		return 0
	}
	fmt.Fprintf(s.stdout, "Updated the shim in %s to golem-exec %s\n", s.binDir(), version)
	return 0
}

// installShims copies this binary into ~/.golem/bin under the shim names. The
// jail keeps that directory unwritable, so a command cannot replace the shell
// the next one runs in.
func (s *setup) installShims() error {
	bin, err := os.ReadFile(s.exe)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.binDir(), 0o700); err != nil {
		return err
	}
	if s.goos == "windows" {
		return s.installWindowsShims(bin)
	}
	target := filepath.Join(s.binDir(), "golem-exec")
	if filepath.Clean(s.exe) != target {
		if err := writeExecutable(target, bin); err != nil {
			return err
		}
	}
	for _, link := range s.shims() {
		if err := shield.LinkShim(link, "golem-exec"); err != nil {
			return err
		}
	}
	return shield.LinkHookShims(s.binDir(), "golem-exec")
}

func writeExecutable(path string, bin []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".golem-exec-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(bin); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (s *setup) editSettings(edit func(*jsonobject.Object) ([]string, error)) ([]string, error) {
	doc, _, err := jsonobject.ReadFile(s.settingsPath())
	if err != nil {
		return nil, err
	}
	changes, err := edit(doc)
	if err != nil || len(changes) == 0 {
		return nil, err
	}
	return changes, jsonobject.WriteFile(s.settingsPath(), doc)
}

func (s *setup) currentShell(cs shield.ClaudeShell) string {
	doc, _, err := jsonobject.ReadFile(s.settingsPath())
	if err != nil {
		return ""
	}
	raw, ok := doc.Get("env")
	if !ok {
		return ""
	}
	env, err := jsonobject.Parse(raw)
	if err != nil {
		return ""
	}
	var v string
	if raw, ok := env.Get(cs.Var()); ok {
		_ = json.Unmarshal(raw, &v)
	}
	return v
}

func (s *setup) uninstall(purge bool) int {
	if s.agentRuns() {
		fmt.Fprintln(s.stdout, "The Golem agent manages the shield on this machine; uninstall the agent to remove it.")
		return 1
	}
	code := 0
	if changes, err := s.editSettings(s.claudeShell().Unwire); err != nil {
		fmt.Fprintf(s.stderr, "golem-exec: could not edit %s: %v\n", s.settingsPath(), err)
		code = 1
	} else {
		for _, c := range changes {
			fmt.Fprintf(s.stdout, "Claude Code: %s\n", c)
		}
	}
	if s.wireAgents(true) != 0 {
		code = 1
	}
	_ = os.RemoveAll(shield.HookShimDir(s.home))
	for _, p := range append(s.shims(), filepath.Join(s.binDir(), "golem-exec"), filepath.Join(s.binDir(), "golem-exec.exe")) {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(s.stderr, "golem-exec: could not remove %s: %v\n", p, err)
			code = 1
		}
	}
	if purge {
		_ = os.Remove(shield.ConfigPath(s.home))
		_ = os.RemoveAll(filepath.Join(s.home, ".golem", "shield"))
	}
	fmt.Fprintln(s.stdout, "Removed the shim. Restart your agents.")
	return code
}

func (s *setup) status() int {
	if s.agentRuns() {
		fmt.Fprint(s.stdout, agentManages)
		return 0
	}
	cs := s.claudeShell()
	shim := "not installed (run: golem-exec install)"
	if cs.Ready(cs.Shim) {
		shim = cs.Shim
	}
	fmt.Fprintf(s.stdout, "shim         %s\n", shim)
	s.statusAgents()
	if s.canJail() {
		fmt.Fprintf(s.stdout, "kernel jail  available\n")
	} else {
		fmt.Fprintf(s.stdout, "kernel jail  not available: %s\n", jailUnavailable(s.goos))
	}
	if s.goos == "linux" {
		s.statusProjectFiles()
	}

	cfgPath := shield.ConfigPath(s.home)
	cfg, found, err := shield.LoadConfig(cfgPath)
	switch {
	case !found:
		fmt.Fprintln(s.stdout, "settings     none, so commands get the baseline")
	case err != nil:
		fmt.Fprintf(s.stdout, "settings     %s is not valid (%v), so every command is locked down\n", cfgPath, err)
		cfg = shield.Config{Lockdown: true}
	default:
		fmt.Fprintf(s.stdout, "settings     %s\n", cfgPath)
	}
	p := cfg.Policy()
	g := p.Effective()
	fmt.Fprintf(s.stdout, "policy       jail %s, lockdown %s\n", onOff(p.Enforce), onOff(p.Tainted()))
	fmt.Fprintf(s.stdout, "             ssh agent %s, docker %s, cloud credentials %s\n", onOff(g.Agent), onOff(g.Docker), onOff(g.Cloud))
	if len(p.EnvAllow)+len(p.EnvDeny) > 0 {
		fmt.Fprintf(s.stdout, "             env allow %v, deny %v\n", p.EnvAllow, p.EnvDeny)
	}
	s.statusConfinement(p)
	return 0
}

// statusConfinement says where commands may write and what they may reach,
// and where this system can't hold that.
func (s *setup) statusConfinement(p shield.Policy) {
	switch {
	case p.Tainted():
		fmt.Fprintln(s.stdout, "writes       the project and temp only (lockdown)")
		fmt.Fprintln(s.stdout, "network      none (lockdown)")
		return
	case p.ConfinedWrites():
		extra := ""
		if len(p.AllowWrite) > 0 {
			extra = fmt.Sprintf(", and %s", strings.Join(p.AllowWrite, ", "))
		}
		fmt.Fprintf(s.stdout, "writes       the project, temp and tool caches%s\n", extra)
	default:
		fmt.Fprintln(s.stdout, "writes       anywhere but the protected files")
	}
	if !p.Proxied() {
		fmt.Fprintln(s.stdout, "network      open")
		return
	}
	hosts := "none yet: add them to \"allowed_hosts\""
	if len(p.AllowedHosts) > 0 {
		hosts = strings.Join(p.AllowedHosts, ", ")
	}
	fmt.Fprintf(s.stdout, "network      allowed hosts only, through a proxy: %s\n", hosts)
	switch s.goos {
	case "windows":
		if on, err := s.firewallOn(); err == nil && on {
			fmt.Fprintln(s.stdout, "             held by the shield's Windows firewall filters")
		} else {
			fmt.Fprintln(s.stdout, "             without the shield's firewall, only programs that use the proxy are held to the list;")
			fmt.Fprintln(s.stdout, "             run `golem-exec firewall install` as administrator to refuse the rest")
		}
	case "linux":
		switch ns := s.namespaces(s.exe); ns {
		case shield.NamespacesOpen:
			fmt.Fprintln(s.stdout, "             held by each command's own network namespace")
		case shield.NamespacesProfiled:
			fmt.Fprintln(s.stdout, "             held by a network namespace, which golem-exec's AppArmor profile lets the jail make")
		default:
			fmt.Fprintln(s.stdout, "             held by Landlock's port rule, which lets a program that ignores the proxy reach any host")
			fmt.Fprintln(s.stdout, "             on the proxy's port: "+namespaceGap(ns))
			s.namespaceFix(ns)
		}
	}
}

// statusProjectFiles says whether the agents' project files (hooks, MCP
// servers, settings) are held, which on Linux takes each command's own
// namespace.
func (s *setup) statusProjectFiles() {
	ns := s.namespaces(s.exe)
	if ns.Held() {
		fmt.Fprintln(s.stdout, "project      the agents' hooks, MCP servers and settings in the work tree are held read-only")
		return
	}
	fmt.Fprintln(s.stdout, "project      the agents' hooks, MCP servers and settings in the work tree are NOT held:")
	fmt.Fprintln(s.stdout, "             "+namespaceGap(ns))
	s.namespaceFix(ns)
}

func namespaceGap(ns shield.Namespaces) string {
	switch ns {
	case shield.NamespacesNoProfile, shield.NamespacesStaleProfile:
		return "AppArmor keeps user namespaces from programs it doesn't name."
	default:
		return "this system lets no program make a user namespace (a container, or user namespaces turned off)."
	}
}

func (s *setup) namespaceFix(ns shield.Namespaces) {
	switch ns {
	case shield.NamespacesStaleProfile:
		fmt.Fprintln(s.stdout, "             The profile's copy of golem-exec is another build; after an upgrade, run again:")
	case shield.NamespacesNoProfile:
		fmt.Fprintln(s.stdout, "             To let the jail make its namespace, run:")
	default:
		return
	}
	fmt.Fprintf(s.stdout, "             sudo %s apparmor install\n", s.exe)
}

// test runs two commands through the installed shim: one must run, and one
// that reads a file the jail always denies must fail.
func (s *setup) test() int {
	cs := s.claudeShell()
	if !cs.Ready(cs.Shim) {
		fmt.Fprintln(s.stderr, "golem-exec: the shim is not installed (run: golem-exec install)")
		return 1
	}
	cfg, _, err := shield.LoadConfig(shield.ConfigPath(s.home))
	if err == nil && !cfg.Policy().Enforce {
		fmt.Fprintln(s.stdout, "Self-test skipped: \"enforce\" is false in ~/.golem/shield.json, so commands run without a jail.")
		return 0
	}
	probe := filepath.Join(s.home, ".golem", "shield", "self-test.txt")
	if err := os.MkdirAll(filepath.Dir(probe), 0o700); err == nil {
		err = os.WriteFile(probe, []byte("golem-exec self-test\n"), 0o600)
	}
	if err != nil {
		fmt.Fprintf(s.stderr, "golem-exec: could not write the self-test file: %v\n", err)
		return 1
	}
	if code, err := s.selfTest(cs.Shim, "true"); err != nil || code != 0 {
		fmt.Fprintf(s.stderr, "golem-exec: self-test FAILED: a plain command did not run through the shim (exit %d, %v)\n", code, err)
		return 1
	}
	if code, err := s.selfTest(cs.Shim, "cat '"+filepath.ToSlash(probe)+"'"); err != nil || code == 0 {
		fmt.Fprintf(s.stderr, "golem-exec: self-test FAILED: a command read %s, which the jail should deny. Do not rely on the jail here.\n", probe)
		return 1
	}
	fmt.Fprintln(s.stdout, "Self-test passed: commands run, and the jail denied a read of ~/.golem.")
	return 0
}

func runThroughShim(shim, command string) (int, error) {
	cmd := exec.Command(shim, "-c", command)
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "CLAUDE_CODE_SESSION_ID=") {
			env = append(env, kv)
		}
	}
	cmd.Env = env
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), nil
	}
	if err != nil {
		return -1, err
	}
	return 0, nil
}

// firewall installs or removes the shield's Windows Filtering Platform
// filters, which hold an allowlisted shell to its proxy. They touch only a
// shell the shim marks, and persist until removed.
func (s *setup) firewall(args []string) int {
	if len(args) != 1 || (args[0] != "install" && args[0] != "remove") {
		fmt.Fprint(s.stderr, cliUsage)
		return 2
	}
	if s.goos != "windows" {
		fmt.Fprintln(s.stderr, "golem-exec: the firewall is for Windows; macOS and Linux hold the network in the kernel jail itself")
		return 1
	}
	if err := changeFirewall(args[0] == "install"); err != nil {
		fmt.Fprintf(s.stderr, "golem-exec: could not %s the firewall filters (%v); run this as administrator\n", args[0], err)
		return 1
	}
	if args[0] == "install" {
		fmt.Fprintln(s.stdout, "Installed the shield's firewall filters: an allowed-hosts network now refuses programs that ignore the proxy.")
	} else {
		fmt.Fprintln(s.stdout, "Removed the shield's firewall filters.")
	}
	return 0
}

// apparmor installs or removes golem-exec's AppArmor profile and the
// root-owned copy it names (apparmor_linux.go).
func (s *setup) apparmor(args []string) int {
	if len(args) != 1 || (args[0] != "install" && args[0] != "remove") {
		fmt.Fprint(s.stderr, cliUsage)
		return 2
	}
	if s.goos != "linux" {
		fmt.Fprintln(s.stderr, "golem-exec: the AppArmor profile is for Linux")
		return 1
	}
	err := changeAppArmor(args[0] == "install", s.exe)
	switch {
	case errors.Is(err, errAppArmorNotNeeded):
		fmt.Fprintln(s.stdout, "This kernel doesn't restrict user namespaces, so the jail makes its own without a profile.")
		return 0
	case err != nil:
		fmt.Fprintf(s.stderr, "golem-exec: could not %s the AppArmor profile: %v\n", args[0], err)
		return 1
	case args[0] == "install":
		fmt.Fprintln(s.stdout, "Installed golem-exec's AppArmor profile: an allowed-hosts network is now held by a network namespace.")
		fmt.Fprintln(s.stdout, "The profile names a copy of this golem-exec; run this again after upgrading.")
	default:
		fmt.Fprintln(s.stdout, "Removed golem-exec's AppArmor profile.")
	}
	return 0
}

func jailUnavailable(goos string) string {
	switch goos {
	case "linux":
		return "this kernel has no Landlock (Linux 5.13 or later, with landlock among the enabled LSMs)"
	case "darwin":
		return "sandbox-exec could not run here, as happens inside another sandbox"
	case "windows":
		return "a restricted token could not be created"
	}
	return "golem-exec has no jail for " + goos
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
