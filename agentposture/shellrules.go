package agentposture

import (
	"regexp"
	"strings"
)

// Some commands run whatever they are given (an interpreter, a shell, eval,
// npx) and some send whatever they are given anywhere (curl, scp), so an allow
// rule for one is any code or any upload, not one tool.

var claudeShellRules = map[string]bool{"Bash": true, "Bash(*)": true, "Bash(:*)": true, "Bash(*:*)": true}

var pythonRE = regexp.MustCompile(`^(python|pypy)[0-9.]*$`)

var anyCodeCommands = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "fish": true, "csh": true, "tcsh": true,
	"pwsh": true, "powershell": true, "cmd": true,
	"node": true, "nodejs": true, "deno": true, "bun": true, "ruby": true, "perl": true, "php": true, "lua": true,
	"osascript": true, "npx": true, "bunx": true, "pnpx": true, "uvx": true,
	"eval": true, "exec": true, "source": true, "env": true, "xargs": true, "sudo": true, "doas": true,
	"nohup": true, "nice": true, "timeout": true, "time": true, "watch": true,
}

var anyCodeRunners = map[string]bool{
	"npm exec": true, "pnpm dlx": true, "pnpm exec": true, "yarn dlx": true, "uv run": true, "deno run": true, "deno eval": true,
}

var uploadCommands = map[string]bool{
	"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true, "socat": true, "scp": true, "sftp": true,
	"rsync": true, "ssh": true, "ftp": true, "http": true, "https": true, "xh": true,
}

var codeFlags = map[string]bool{"-c": true, "-lc": true, "-e": true, "--eval": true, "-p": true, "--print": true}

type shellRuleKind int

const (
	shellNone shellRuleKind = iota
	shellAny
	shellAnyCode
	shellUpload
)

// shellRule reads the command inside Claude Code's Bash(...) or Cursor's
// Shell(...). Claude Code allows a prefix only with a trailing wildcard
// (python3:*, python3 *), and Bash(python3) is that exact command; Cursor's
// Shell(x) matches the command's first word, wildcard or not.
func shellRule(rule, tool string, prefixOnly bool) (kind shellRuleKind, cmd string) {
	r := strings.TrimSpace(rule)
	if strings.EqualFold(r, tool) {
		return shellAny, ""
	}
	inner, ok := strings.CutPrefix(r, tool+"(")
	if !ok || !strings.HasSuffix(inner, ")") {
		return shellNone, ""
	}
	inner = strings.TrimSpace(strings.TrimSuffix(inner, ")"))
	switch {
	case strings.HasSuffix(inner, ":*"):
		inner = strings.TrimSuffix(inner, ":*")
	case strings.HasSuffix(inner, "*"):
		inner = strings.TrimSuffix(inner, "*")
	case prefixOnly:
		return shellNone, ""
	}
	words := strings.Fields(strings.TrimRight(inner, ": "))
	if len(words) == 0 || words[0] == "*" {
		return shellAny, ""
	}
	name := exeName(words[0])
	rest := words[1:]
	if len(rest) > 0 && anyCodeRunners[name+" "+rest[0]] {
		return shellAnyCode, name + " " + rest[0]
	}
	if uploadCommands[name] {
		return shellUpload, name
	}
	if !anyCodeCommands[name] && !pythonRE.MatchString(name) {
		return shellNone, ""
	}
	for _, w := range rest {
		if !codeFlags[w] {
			return shellNone, ""
		}
	}
	return shellAnyCode, strings.Join(words, " ")
}

func claudeShellRule(rule string) (shellRuleKind, string) {
	if claudeShellRules[strings.ReplaceAll(rule, " ", "")] {
		return shellAny, ""
	}
	return shellRule(rule, "Bash", true)
}

func cursorShellRule(rule string) (shellRuleKind, string) { return shellRule(rule, "Shell", false) }

func broadestShellRule(rules []string, read func(string) (shellRuleKind, string)) (rule, cmd string, kind shellRuleKind) {
	for _, r := range rules {
		k, c := read(r)
		if k == shellAny {
			return r, "", shellAny
		}
		if k == shellAnyCode && kind != shellAnyCode {
			rule, cmd, kind = r, c, k
		}
	}
	return rule, cmd, kind
}

func shellDetail(kind shellRuleKind, cmd, anyCommand string) string {
	if kind == shellAnyCode {
		return "any code runs without asking, through " + cmd
	}
	return anyCommand
}

func ruleIs(read func(string) (shellRuleKind, string), kinds ...shellRuleKind) func(string) bool {
	return func(r string) bool {
		k, _ := read(r)
		for _, want := range kinds {
			if k == want {
				return true
			}
		}
		return false
	}
}
