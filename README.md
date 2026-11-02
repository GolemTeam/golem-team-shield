# golem-team-shield

Two free tools for the AI coding agents on your machine, from
[Golem](https://golem.team): a check of how they are set up to run, and a kernel
jail around every shell command they run. Neither needs an account, and neither
sends anything anywhere.

| | What it does |
|---|---|
| `golem-check` | Reads your agents' settings and prints the ones that let them act without asking. |
| `golem-exec` | Runs each shell command an agent starts inside a kernel jail: Seatbelt on macOS, Landlock and seccomp on Linux, AppContainer on Windows. |

## golem-check

```sh
go install github.com/GolemTeam/golem-team-shield/cmd/golem-check@latest
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

## golem-exec

`golem-exec` is a shell shim. The agent runs it as its shell, and it runs the
real shell, with the same arguments, inside a jail. Everything the command
starts inherits the jail.

On its own, every command gets the baseline jail. The command cannot:

- read private SSH keys, GnuPG private keys, `.netrc`, `.git-credentials` or
  shell history;
- write to `~/.ssh`, the agents' settings and hooks, your shell startup files,
  your git config, or the directory the shim is installed in.

For Claude Code on macOS or Linux:

```sh
go install github.com/GolemTeam/golem-team-shield/cmd/golem-exec@latest
mkdir -p ~/.golem/bin
cp "$(go env GOPATH)/bin/golem-exec" ~/.golem/bin/golem-exec
ln -sf golem-exec ~/.golem/bin/golem-zsh     # or golem-bash
export CLAUDE_CODE_SHELL=~/.golem/bin/golem-zsh
```

The name decides which shell runs: `golem-zsh` runs `/bin/zsh` and `golem-bash`
runs `/bin/bash`. The shim never looks the shell up on `PATH`. Install it under
`~/.golem/bin`, because the jail keeps that directory unwritable, so a command
cannot replace the shim the next command runs in.

On Windows, copy `golem-exec.exe` to `%USERPROFILE%\.golem\bin\bash.exe` and set
`CLAUDE_CODE_GIT_BASH_PATH` to that path. It runs Git for Windows' `bash.exe`.

### With Golem

With the Golem agent running, `golem-exec` asks it for each session's policy
instead of using the baseline. The agent, called the witness in the code,
decides that policy. After a web fetch, a prompt injection or a jail denial in
a session, its later commands lose:

- the network;
- cloud and package-registry credentials;
- the SSH agent and the keychain;
- writes outside the workspace.

Golem also records what each agent did, enforces rules on its tool calls, and
runs untrusted repositories, pages and files in a sandbox. See
[golem.team](https://golem.team) and [docs.golem.team/shield](https://docs.golem.team/shield).

## Packages

| Package | |
|---|---|
| [`shield`](shield/) | The jail's policy, and the compilers that turn it into a Seatbelt profile, Landlock and seccomp rules, or an AppContainer. |
| [`agentposture`](agentposture/) | The settings scan behind `golem-check`. It reads files and nothing else. |

## License

Apache-2.0. See [LICENSE](LICENSE).
