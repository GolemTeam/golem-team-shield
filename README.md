# golem-team-shield

[![Release](https://img.shields.io/github/v/release/GolemTeam/golem-team-shield)](https://github.com/GolemTeam/golem-team-shield/releases/latest)
[![Test](https://github.com/GolemTeam/golem-team-shield/actions/workflows/test.yml/badge.svg)](https://github.com/GolemTeam/golem-team-shield/actions/workflows/test.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/GolemTeam/golem-team-shield.svg)](https://pkg.go.dev/github.com/GolemTeam/golem-team-shield)

Two free tools for the AI coding agents on your machine, from
[Golem](https://golem.team). Neither needs an account, and neither sends
anything anywhere.

| | What it does |
|---|---|
| `golem-exec` | Runs every shell command Claude Code starts inside a kernel jail: Seatbelt on macOS, Landlock and seccomp on Linux, a restricted token on Windows. |
| `golem-check` | Reads your agents' settings and prints the ones that let them act without asking. |

## What the jail stops

A prompt injection that gets an agent to run `cat ~/.ssh/id_ed25519`, or to add
a line to `~/.zshrc`, fails. Here is exactly what a jailed command can and can't
do with the default settings:

| Denied | Still allowed |
|---|---|
| Reading private SSH and GPG keys, `.netrc`, `.git-credentials` and shell history | The network |
| Writing to `~/.ssh`, your shell startup files, git config, `~/Library/LaunchAgents`, and the agents' settings and hooks | Cloud credentials: `~/.aws`, gcloud, Azure, kube, and Docker, npm and PyPI logins (turn these off with `--strict`) |
| Secret-shaped environment variables (`*TOKEN*`, `*SECRET*`, `*API_KEY*`, `GH_*`, `ANTHROPIC_*`, `OPENAI_*` and others), which are removed | The SSH agent, the keychain and the Docker socket |
| Reading or writing `~/.golem`, where the jail's own settings live | Everything else in your home directory and your projects |

So it stops the obvious theft and persistence. It does not stop a command from
sending what it can read to the internet. Lockdown does (see
[Settings](#settings)), at the cost of the network for every command.

It jails shell commands only. Claude Code's own Read, Write and fetch tools
don't go through a shell, so they are not jailed. For now it works with Claude
Code only: other agents have no setting that names the shell they run. Linux
and Windows each have a few gaps of their own, listed under
[what the jail does not cover](https://docs.golem.team/shield#what-the-jail-does-not-cover).

## Install

### With Homebrew

On macOS or Linux:

```sh
brew install golemteam/golem-team/golem-team-shield
golem-exec install
```

### From a release

On macOS or Linux:

```sh
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
base=https://github.com/GolemTeam/golem-team-shield/releases/latest/download
curl -fsSLO "$base/golem-team-shield_${os}_${arch}.tar.gz"
curl -fsSLO "$base/checksums.txt"
grep "_${os}_${arch}.tar.gz" checksums.txt | shasum -a 256 -c
tar -xzf "golem-team-shield_${os}_${arch}.tar.gz" golem-exec golem-check
./golem-exec install
```

On Linux without `shasum`, use `sha256sum -c` instead. If you download in a
browser on a Mac, clear the quarantine flag before running the binaries:
`xattr -d com.apple.quarantine golem-exec golem-check`.

On Windows, in PowerShell, with [Git for Windows](https://git-scm.com/download/win)
installed (Claude Code runs its commands in Git Bash there):

```powershell
$base = 'https://github.com/GolemTeam/golem-team-shield/releases/latest/download'
Invoke-WebRequest "$base/golem-team-shield_windows_amd64.zip" -OutFile shield.zip
Invoke-WebRequest "$base/checksums.txt" -OutFile checksums.txt
(Get-FileHash shield.zip -Algorithm SHA256).Hash.ToLower()   # must match checksums.txt
Expand-Archive shield.zip -DestinationPath golem-shield
.\golem-shield\golem-exec.exe install
```

### With Go

```sh
go install github.com/GolemTeam/golem-team-shield/cmd/golem-exec@latest
go install github.com/GolemTeam/golem-team-shield/cmd/golem-check@latest
golem-exec install
```

### What `golem-exec install` does

1. It copies itself to `~/.golem/bin`, under the names Claude Code runs as a
   shell: `golem-zsh` and `golem-bash`, or `bash.exe` on Windows. The jail keeps
   that directory unwritable, so no command can replace the shell the next
   command runs in.
2. It writes the settings, `~/.golem/shield.json`, with every setting named.
3. It points Claude Code at the jail. It sets `CLAUDE_CODE_SHELL` in
   `~/.claude/settings.json`; on Windows it sets `CLAUDE_CODE_GIT_BASH_PATH` and
   turns off Claude Code's PowerShell tool, whose commands would not be jailed.
   If you set Claude Code's shell yourself, it leaves that alone and says how to
   change it.
4. It tests the jail. A plain command must run, and a read of `~/.golem` must
   be denied.

It refuses on a machine where the jail can't be built: Linux older than 5.13 or
without Landlock enabled, or macOS inside another sandbox. Then restart Claude
Code.

```sh
golem-exec status      # what is installed, and what commands get
golem-exec test        # run the self-test again
golem-exec uninstall   # put Claude Code's shell back (--purge also removes the settings)
```

Claude Code runs the copy in `~/.golem/bin`, not the one on your PATH. Homebrew
updates that copy after each `brew upgrade`. Installed another way, run
`golem-exec install --refresh` after upgrading: it replaces the installed shim
and changes nothing else. `man golem-exec` and `man golem-check` describe every
command and setting; the release archives carry the pages in `man/`.

## Settings

`~/.golem/shield.json`:

```json
{
  "enforce": true,
  "lockdown": false,
  "ssh_agent": true,
  "docker": true,
  "cloud_credentials": true,
  "env_allow": [],
  "env_deny": []
}
```

| Setting | What it does |
|---|---|
| `enforce` | `false` runs commands without a jail. |
| `lockdown` | Every command loses the network, the SSH agent, Docker, cloud credentials and writes outside the project it runs in. On Windows, which can't take the network from a command, commands don't run at all. |
| `ssh_agent` | The SSH agent and the keychain. |
| `docker` | The Docker socket. |
| `cloud_credentials` | `~/.aws`, gcloud, Azure, kube and the Docker, npm and PyPI logins, and the cloud tools' variables (`AWS_*`, `KUBECONFIG` and others). `golem-exec install --strict` writes `false`. |
| `env_allow` | Secret-shaped variables to keep, by name or as a `PREFIX*`. Ignored in lockdown. |
| `env_deny` | Variables to remove, by name or as a `PREFIX*`. |

Changes apply to the next command; there is nothing to restart. The jail can
neither read nor write `~/.golem`, so the agent being watched can't loosen its
own jail. A name the shim doesn't know, or a file that isn't valid JSON, locks
every command down until it is fixed, so a typo can only make the jail
tighter. `golem-exec status` shows what commands get.

## golem-check

```sh
golem-check          # what is risky, worst first
golem-check -json    # every finding, informational ones included
```

It reads the settings of Claude Code (including managed settings and MDM
profiles), Cursor, Codex, Gemini CLI, Devin, and the VS Code family of editors
(VS Code, VS Code Insiders, VSCodium, Cursor, Windsurf, Antigravity). It also
reads the settings of each repository Claude Code has opened. It reports:

- permission prompts turned off;
- every command allowed;
- every folder trusted;
- no sandbox.

It reports a setting's name and value, never a file's contents.

## With Golem

The Golem agent is free to use and needs no account. With no key it runs on
your machine only, and sends nothing anywhere:

```sh
curl -fsSL https://app.golem.team/install.sh | sh
```

On Windows, in PowerShell run as administrator:

```powershell
iwr -useb https://app.golem.team/install.ps1 | iex
```

It replaces what you set up above rather than adding to it. It installs its own
`golem-exec` in `~/.golem/bin`, under the same names, so `CLAUDE_CODE_SHELL`
stays as it is, and `golem check` is the same report as `golem-check`. With the
agent running, it decides each command's policy and `~/.golem/shield.json` is
not used.

What the agent adds is a policy per session instead of one for every command.
After a web fetch, a prompt injection or a jail denial in a session, that
session's later commands lose:

- the network;
- cloud and package-registry credentials;
- the SSH agent and the keychain;
- writes outside the workspace.

It also lets agents hand untrusted repositories, pages and files to a sandbox,
and it enforces built-in rules on their tool calls. `golem connect --key`
links the machine to a Golem workspace, which records what each agent did and
shows it in a console. See [golem.team](https://golem.team) and
[docs.golem.team/shield](https://docs.golem.team/shield).

To go back, uninstall the agent and run `golem-exec install` again.

## Packages

| Package | |
|---|---|
| [`shield`](shield/) | The jail's policy, its settings file, and the compilers that turn it into a Seatbelt profile, Landlock and seccomp rules, or a restricted token's deny entries. |
| [`agentposture`](agentposture/) | The settings scan behind `golem-check`. It reads files and nothing else. |

## License

Apache-2.0. See [LICENSE](LICENSE).
