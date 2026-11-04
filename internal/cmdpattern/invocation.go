package cmdpattern

import (
	"path"
	"strings"
)

// Invocation is one simple command the shell would run, unmasked: what a
// detection rule asks of a command line. A heredoc body, a commit message and
// a quoted argument are data handed to a command, never a command of their
// own, so a rule over Invocations matches what the line does rather than what
// its text mentions.
type Invocation struct {
	Program string // empty for a line that only redirects
	Args    []string
	Reads   []string // targets of <
	Writes  []string // targets of >, >>, &> and >|
	Creates []string // the Writes that empty the file first: not >> or <>
	// StdoutToFile is whether a redirect sends stdout to a file (>, >>, 1>, &>),
	// so whoever ran the line sees none of it. 2>/dev/null leaves it false.
	StdoutToFile bool
	Sudo         bool
	PipedFrom    string
	// SubstitutedIn is where a command run inside $(...) or backticks sends
	// its output: "=" for a variable assignment, else the program whose
	// argument it fills. Empty for a command the line runs directly.
	SubstitutedIn string
}

// maxInvocations is higher than maxCommands because a rule must still see the
// command at the end of a padded line.
const maxInvocations = 256

type invocations struct {
	out []Invocation
}

// Invocations returns the simple commands in line in the order they run. It
// follows the wrappers Parse does (sudo, env, xargs, timeout, bash -c, eval)
// and, unlike Parse, also command substitutions and a heredoc fed to a shell,
// since those run too.
func Invocations(line string) []Invocation {
	if len(line) > maxInput {
		line = line[:maxInput]
	}
	p := &parser{index: map[string]int{}, inv: &invocations{}}
	p.line(line, ctx{}, 0)
	return p.inv.out
}

// substWrappers run the command after them, so a substitution's output goes to
// that command rather than to the wrapper.
var substWrappers = set("sudo", "doas", "env", "nice", "nohup", "time", "command", "exec", "builtin")

func (p *parser) substitutions(words []word, redirs []token, c ctx, depth int) {
	if depth >= maxDepth {
		return
	}
	inner := c
	inner.indirect = true
	outer := ""
	for _, w := range words {
		if isAssignment(w) || strings.Contains(w.lit, substMark) || strings.HasPrefix(w.lit, "-") || substWrappers[path.Base(w.lit)] {
			continue
		}
		outer = path.Base(w.lit)
		break
	}
	for _, w := range words {
		inner.substIn = outer
		if isAssignment(w) {
			inner.substIn = "="
		}
		for _, s := range w.subst {
			p.line(s, inner, depth+1)
		}
	}
	inner.substIn = outer
	for _, r := range redirs {
		for _, s := range r.w.subst {
			p.line(s, inner, depth+1)
		}
	}
}

func (p *parser) invoke(words []word, redirs []token, c ctx, depth int, f feed) string {
	inv := Invocation{Sudo: c.sudo, PipedFrom: f.prev, SubstitutedIn: c.substIn}
	if len(words) > 0 {
		if !strings.Contains(words[0].lit, substMark) {
			inv.Program = path.Base(words[0].lit)
		}
		for _, w := range words[1:] {
			inv.Args = append(inv.Args, strings.ReplaceAll(w.lit, substMark, ""))
		}
	} else if c.sudo {
		inv.Program = "sudo"
	}
	var stdin *word
	for i, r := range redirs {
		target := strings.ReplaceAll(r.w.lit, substMark, "")
		switch {
		case isHeredoc(r.op) || strings.HasSuffix(r.op, "<<<"):
			stdin = &redirs[i].w
		case (strings.HasSuffix(r.op, ">&") || strings.HasSuffix(r.op, "<&")) && (isDigits(target) || target == "-"):
		case target == "":
		case strings.Contains(r.op, ">"):
			inv.Writes = append(inv.Writes, target)
			inv.StdoutToFile = inv.StdoutToFile || redirectsStdout(r.op)
			if strings.HasSuffix(r.op, "<>") {
				inv.Reads = append(inv.Reads, target)
			} else if !strings.Contains(r.op, ">>") {
				inv.Creates = append(inv.Creates, target)
			}
		default:
			inv.Reads = append(inv.Reads, target)
		}
	}
	if inv.Program == "" && len(inv.Writes) == 0 && len(inv.Reads) == 0 {
		return ""
	}
	if len(p.inv.out) < maxInvocations {
		p.inv.out = append(p.inv.out, inv)
	}
	if stdin != nil && shells[inv.Program] && depth < maxDepth && readsScriptFromStdin(words[1:]) {
		inner := c
		inner.indirect = true
		p.line(stdin.lit, inner, depth+1)
	}
	return inv.Program
}

func redirectsStdout(op string) bool {
	body := strings.TrimLeft(op, "0123456789")
	fd := op[:len(op)-len(body)]
	return strings.HasPrefix(body, "&>") || (fd == "" || fd == "1") && strings.HasPrefix(body, ">")
}

// readsScriptFromStdin is whether a shell given these arguments runs its stdin,
// as `bash <<EOF` and `sh -s` do: no script file and no -c.
func readsScriptFromStdin(args []word) bool {
	for _, a := range args {
		if a.quoted || !strings.HasPrefix(a.lit, "-") {
			return false
		}
		if !strings.HasPrefix(a.lit, "--") && strings.Contains(a.lit[1:], "c") {
			return false
		}
	}
	return true
}
