// golem-check grades how the AI coding agents on this machine are set up: the
// settings that let them act without asking, what protects their shells, and
// the rest of docs/design-golem-check-report.md as it lands. It reads their
// files and sends nothing anywhere.
package main

import (
	"cmp"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/GolemTeam/golem-team-shield/agentposture"
	"github.com/GolemTeam/golem-team-shield/agentposture/checkcmd"
	"github.com/GolemTeam/golem-team-shield/shield"
)

// version is set at release (-X main.version=...).
var version = "dev"

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	return checkcmd.Run(args, stdout, stderr, checkcmd.Options{
		Name: "golem-check", Version: version, Machine: scanMachine, Footer: footer,
	})
}

func scanMachine() agentposture.Result {
	env := agentposture.DefaultEnv()
	res := agentposture.ScanAll(env)
	res.Add(checkcmd.ShellJailItems(shield.CoverageOf(shield.CoverageEnv{Home: env.Home, GOOS: env.GOOS, LoginShell: os.Getenv("SHELL"), CodexHomes: env.CodexHomes, OpenClawDir: os.Getenv("OPENCLAW_STATE_DIR")}))...)
	return res
}

func footer(out io.Writer) error {
	fmt.Fprintln(out, agentposture.NotRead)
	fmt.Fprintln(out)
	if agentInstalled(agentposture.DefaultEnv().Home, runtime.GOOS) {
		_, err := fmt.Fprintln(out, "The Golem agent is installed here: `golem check` adds what only it sees.")
		return err
	}
	fmt.Fprintln(out, "Put every shell command your agents run in a kernel jail, and run untrusted repos,")
	fmt.Fprintln(out, "pages and files in a sandbox, free and with no account:")
	_, err := fmt.Fprintln(out, "  "+installCommand(runtime.GOOS))
	return err
}

// systemBinDirs is where the installer puts the agent outside the home
// directory; tests clear it.
var systemBinDirs = []string{"/usr/local/bin"}

// agentInstalled reports the Golem agent's binary where its installer puts
// it, or anywhere on PATH. It looks at files only: ~/.golem, where the agent
// keeps its state, is unreadable from inside the shell jail, and probing the
// agent's port would be the network this check never uses.
func agentInstalled(home, goos string) bool {
	name, dirs := "golem", append([]string(nil), systemBinDirs...)
	if home != "" {
		dirs = append(dirs, filepath.Join(home, ".local", "bin"))
	}
	if goos == "windows" {
		name, dirs = "golem.exe", []string{filepath.Join(cmp.Or(os.Getenv("ProgramFiles"), `C:\Program Files`), "Golem")}
	}
	if d := os.Getenv("GOLEM_INSTALL_DIR"); d != "" {
		dirs = append(dirs, d)
	}
	for _, dir := range append(dirs, filepath.SplitList(os.Getenv("PATH"))...) {
		if dir == "" {
			continue
		}
		info, err := os.Stat(filepath.Join(dir, name))
		if err == nil && info.Mode().IsRegular() && (goos == "windows" || info.Mode().Perm()&0o111 != 0) {
			return true
		}
	}
	return false
}

// installCommand installs the Golem agent, which with no key runs on this
// machine only. On Windows it needs PowerShell run as administrator.
func installCommand(goos string) string {
	if goos == "windows" {
		return "iwr -useb https://app.golem.team/install.ps1 | iex   (PowerShell, as administrator)"
	}
	return "curl -fsSL https://app.golem.team/install.sh | sh"
}
