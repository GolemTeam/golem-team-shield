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
| `golem-exec` | Runs every shell command Claude Code, Codex, Gemini CLI, Cursor and Copilot CLI start inside a kernel jail: Seatbelt on macOS, Landlock and seccomp on Linux, a restricted token on Windows. |
| `golem-check` | Grades how your agents are set up, from their run modes and permissions to their MCP servers, skills, hooks and stored secrets, and says what to fix. |

## What the jail stops

A prompt injection that gets an agent to run `cat ~/.ssh/id_ed25519`, or to add
a line to `~/.zshrc`, fails. Here is exactly what a jailed command can and can't
do with the default settings:

| Denied | Still allowed |
|---|---|
| Reading private SSH and GPG keys, `.netrc`, `.git-credentials` and shell history | The network |
| Reading or writing browser profiles (cookies, saved logins), chat apps (Slack, Discord, Teams, Signal, Telegram, WhatsApp), password managers' data (1Password, Bitwarden, `pass`), mail and Messages | |
| Writing to `~/.ssh`, your shell startup files, git config, `~/Library/LaunchAgents`, and the agents' settings and hooks | Cloud credentials: `~/.aws`, gcloud, Azure, kube, and Docker, npm and PyPI logins (turn these off with `--strict`) |
| Secret-shaped environment variables (`*TOKEN*`, `*SECRET*`, `*API_KEY*`, `GH_*`, `ANTHROPIC_*`, `OPENAI_*` and others), which are removed | The SSH agent, the keychain and the Docker socket |
| Reading or writing `~/.golem`, where the jail's own settings live | Everything else in your home directory and your projects |

So it stops the obvious theft and persistence. With the default settings it
does not stop a command from sending what it can read to the internet. Two
settings tighten it, as far as Claude Code's own sandbox goes or further:

- `"network": "allowlist"` lets commands reach only the hosts in
  `allowed_hosts`, through a proxy `golem-exec` runs for each command.
  Anything that ignores the proxy, DNS included, is refused by the kernel. A
  refused host is named in the command's output.
- `"writes": "workspace"` keeps writes to the project, temp and the tool
  caches (`~/.cache`, `~/.npm`, `~/go/pkg/mod`, `~/Library/Caches` and
  others), plus `allow_write`. A new install turns it on; a settings file
  from before keeps `"anywhere"`.

Lockdown takes the network away entirely (see [Settings](#settings)).

It jails shell commands only. An agent's own file and fetch tools don't go
through a shell, so they are not jailed. Linux and Windows each have a few gaps
of their own, listed under
[what the jail does not cover](https://docs.golem.team/shield#what-the-jail-does-not-cover).

### Which agents

| Agent | How its commands reach the jail | Where |
|---|---|---|
| Claude Code | Its shell setting, `CLAUDE_CODE_SHELL`, names the shim | macOS, Linux, Windows |
| Codex | Its `PreToolUse` hook rewrites each command to run through the shim. Codex asks you to approve the new hook once | macOS, Linux; Windows with `--all-agents` |
| Gemini CLI | Its `BeforeTool` hook, the same way | macOS, Linux; Windows with `--all-agents` |
| Cursor (the editor's agent and `cursor-agent`) | Its `preToolUse` hook, the same way. If the hook fails, the command is refused | macOS, Linux |
| Copilot CLI | Its `preToolUse` hook, from `~/.copilot/hooks/golem-shield.json`. If the hook fails, the command is refused | macOS, Linux; Windows with `--all-agents` |
| Devin (Desktop and CLI) | Its `PreToolUse` hook, in `~/.config/devin/config.json`. Its `Exec(…)` rules may see only the wrapper, so only with `--all-agents` | with `--all-agents` |

The rewritten command is a plain `bash -c '…'` or `zsh -c '…'`, so the agent
still asks you about the command it meant to run, and your allow and deny rules
still match it. On Windows these agents run PowerShell, and the rewrite there is
a PowerShell command that runs the shim, so their own approval would see only
that wrapper, not the command: one "always allow" could then approve every later
command, each still jailed, and Codex's dangerous-command warnings would no
longer fire. They are rewritten there only with `golem-exec install
--all-agents` (`"jail_past_approval": true`), and so is Devin everywhere. On macOS, a command an agent runs inside its own
sandbox (Codex's default, or Cursor's or Gemini CLI's when turned on) stays in
that sandbox, because macOS can't put one sandbox inside another. On Linux the
two stack.

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
4. It adds its hook to Codex (`~/.codex/hooks.json`), Gemini CLI
   (`~/.gemini/settings.json`) and Cursor (`~/.cursor/hooks.json`), each only
   if that agent is installed, next to any hooks you already have.
5. It tests the jail. A plain command must run, and a read of `~/.golem` must
   be denied.

It refuses on a machine where the jail can't be built: Linux older than 5.13 or
without Landlock enabled, or macOS inside another sandbox. Then restart your
agents.

```sh
golem-exec status      # what is installed, each agent's coverage, and what commands get
golem-exec test        # run the self-test again
golem-exec uninstall   # put Claude Code's shell back and take the hooks out (--purge also removes the settings)
```

Your agents run the copy in `~/.golem/bin`, not the one on your PATH. Homebrew
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
  "env_deny": [],
  "writes": "anywhere",
  "allow_write": [],
  "network": "open",
  "allowed_hosts": [],
  "jail_past_approval": false
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
| `writes` | `"workspace"` keeps writes to the project (the git repository a command runs in, or its working directory outside one), temp, the tool caches and `allow_write`; `"anywhere"` denies only the protected files. A new install writes `"workspace"`; a file without the key writes anywhere. On Windows the shell runs at low integrity and the project, temp and caches are labelled low, a label they keep. |
| `allow_write` | More places a `"workspace"` command may write: absolute paths or `~/…`, such as `~/go/bin`. One that holds your home directory is ignored. |
| `network` | `"allowlist"` lets commands reach only `allowed_hosts`, through a proxy; everything else, DNS included, is refused. `"open"` (the default) leaves the network alone. On Linux it uses a network namespace, or where the kernel allows none, Landlock's port rule, which lets a program that ignores the proxy reach any host on the proxy's port. Ubuntu allows a namespace only to programs AppArmor names: `sudo ~/.golem/bin/golem-exec apparmor install` adds a profile for a root-owned copy of golem-exec, and `golem-exec status` says when it needs running again after an upgrade. On Windows the network is held by firewall filters you install once from an administrator prompt, `golem-exec firewall install`; without them only programs that use the proxy are held to the list. |
| `allowed_hosts` | `example.com`, `*.example.com` (its subdomains) or `*` (any public host, everything recorded). Any port. `localhost` lets commands reach servers on this machine, a test server they start included; without it loopback is refused. The cloud metadata address is never reachable. With the network confined, `open` and AppleScript can't hand a URL to another app on macOS. |
| `jail_past_approval` | `true` also jails the agents whose own approval would see only the jail's wrapper: Codex, Gemini CLI and Copilot CLI on Windows, and Devin. `golem-exec install --all-agents` writes it and adds their hooks. Off by default. |

Changes apply to the next command; there is nothing to restart. The jail can
neither read nor write `~/.golem`, so the agent being watched can't loosen its
own jail. A name the shim doesn't know, or a file that isn't valid JSON, locks
every command down until it is fixed, so a typo can only make the jail
tighter. `golem-exec status` shows what commands get.

## golem-check

```sh
golem-check                     # the grade, each area's score, and what to fix, worst first
golem-check -json               # every finding, informational ones included (-with-score adds the grade)
golem-check -html -o report.html   # one self-contained page to hand a security team
golem-check -repo .             # only what this repository brings to anyone who clones it
golem-check -repo . -sarif -o golem-check.sarif -fail-on suspicious   # for CI and GitHub code scanning
```

`-repo` reads the agent files a repository carries (`.claude/`, `.mcp.json`,
`.cursor/`, `CLAUDE.md`, `AGENTS.md`, skills and the rest) and nothing from your
home directory. `-sarif` writes SARIF 2.1.0 for GitHub code scanning, and
`-fail-on suspicious` or `-fail-on dangerous` exits 3 when a finding is at
least that severe, so a build can stop on it.

### In GitHub Actions

```yaml
permissions:
  contents: read
  security-events: write   # to upload the findings to code scanning
steps:
  - uses: actions/checkout@v4
  - uses: GolemTeam/golem-team-shield@v0.2.0
    with:
      fail-on: dangerous     # or suspicious, or none
```

The action downloads the `golem-check` release it is pinned to (v0.2.0 or later),
checks it against the release's `checksums.txt`, prints the report in the job
log, uploads the SARIF report to code scanning (`upload-sarif: false` skips
that), sets the `grade` output, and fails the job on a finding at least as severe
as `fail-on`. It reads only the checked-out repository, follows no link out of
it, and needs no token beyond the job's own.

It grades the AI coding agents on your machine out of 100, and scores each
area:

| Area | What it looks for |
|---|---|
| Run modes | Permission prompts turned off, every command allowed, every folder trusted |
| Permissions | Allow rules that let an agent run any command, write any file, fetch any page or call any MCP tool, and every cloned repository's MCP servers starting on their own |
| MCP servers | Servers started by piping a download into a shell, reached over plain HTTP, run from an unpinned package or image, given your whole disk, or run in a privileged container |
| Instructions and skills | Skills, rules files and agent instructions that tell the agent to hide things from you, send secrets somewhere, or ignore its instructions |
| Hooks | Hooks that send data out, run a script other users can change or one that doesn't exist, or hide their own failures |
| Secrets | Keys and tokens written into agent settings and MCP configs, especially in a repository, and agents' sign-in files other users can read |
| Plugin sources | Plugin marketplaces a cloned repository adds, marketplaces from outside the agent's vendor, and sources fetched over plain HTTP |
| Protections | Which agents run their commands in a sandbox or the Golem jail |

It reads Claude Code (including managed settings and MDM profiles), Cursor,
Codex, Gemini CLI, Devin, and the VS Code family of editors (VS Code, VS Code
Insiders, VSCodium, Cursor, Windsurf, Antigravity), and the settings of each
repository Claude Code has opened.

It reads files and nothing else. It never starts an MCP server, so it can't
see the tool descriptions a server sends; the Golem agent checks those as your
agents receive them. It names a secret's file and setting, never the secret
itself.

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
stays as it is, and `golem check` is the same command as `golem-check`. With the
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
