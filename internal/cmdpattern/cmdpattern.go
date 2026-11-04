// Package cmdpattern turns a shell command line into the command assets the
// Security Inventory lists: the program, the program and its subcommand, and a
// masked pattern of the whole invocation, each part of a compound line on its own.
//
// The witness computes these before a call runs and conversation-worker computes
// them afterwards from the ledger. A decision made in the console only ever
// matches a call if both arrive at byte-identical keys, so everything here is a
// pure function of the command text: no environment, no filesystem, no clock.
//
// A pattern's category is derived from the same tokens that render it, and every
// token that can change the category stays readable in the pattern (flags, URL
// hosts, sensitive paths, variable names, the tags on opaque strings). One
// pattern therefore always carries one category, which is what lets the
// inventory store the category on the pattern's row.
package cmdpattern

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
	"strings"
	"unicode/utf8"
)

// Category is what a command does, from a fixed table.
type Category string

const (
	ReadOnly         Category = "read_only"
	BuildTest        Category = "build_test"
	VersionControl   Category = "version_control"
	InstallsPackages Category = "installs_packages"
	Network          Category = "network"
	RunsFetchedCode  Category = "runs_fetched_code"
	DestroysData     Category = "destroys_data"
	Credentials      Category = "credentials"
	Privilege        Category = "privilege"
	Persistence      Category = "persistence"
	Other            Category = "other"
)

// severity orders categories so that a pattern doing two things is filed under
// the worse one. Its ATT&CK ids keep the rest.
var severity = map[Category]int{
	ReadOnly:         0,
	BuildTest:        1,
	VersionControl:   2,
	Other:            3,
	InstallsPackages: 4,
	Network:          5,
	Persistence:      6,
	Credentials:      7,
	DestroysData:     8,
	Privilege:        9,
	RunsFetchedCode:  10,
}

// Worse returns whichever of a and b ranks higher.
func Worse(a, b Category) Category {
	if severity[b] > severity[a] {
		return b
	}
	return a
}

// PathClass is where the executable was run from. A binary run out of /tmp is
// a finding on its own, so the class is part of the pattern.
type PathClass string

const (
	OnPath PathClass = ""
	System PathClass = "system"
	Home   PathClass = "home"
	Repo   PathClass = "repo"
	Tmp    PathClass = "tmp"
)

// Command is one simple command out of a command line.
type Command struct {
	Program   string // basename of the executable, or the package a runner fetched
	Sub       string // "git push" when Program has subcommands, else ""
	Pattern   string // the masked invocation, at most MaxLen bytes
	PathClass PathClass
	Category  Category
	Attack    []string
	Indirect  bool // reached through a runner such as env, xargs, npx or bash -c
	Sudo      bool
}

// MaxLen bounds Program, Sub and Pattern. They are database keys.
const MaxLen = 255

const (
	maxInput    = 256 << 10
	maxCommands = 64
	maxDepth    = 4
)

// Parse returns the commands in line, deduplicated by pattern and in the order
// they first appear.
func Parse(line string) []Command {
	if len(line) > maxInput {
		line = line[:maxInput]
	}
	p := &parser{index: map[string]int{}}
	p.line(line, ctx{}, 0)
	return p.out
}

type ctx struct {
	sudo     bool
	indirect bool
	substIn  string
}

// feed is what a pipe hands the next command: the nearest program upstream
// that fetches from the network, if any.
type feed struct {
	fetcher string
	prev    string
}

type parser struct {
	out   []Command
	index map[string]int
	inv   *invocations
}

type segment struct {
	words  []word
	redirs []token
}

func (p *parser) line(s string, c ctx, depth int) {
	var pipeline []segment
	cur := segment{}
	flush := func(endsPipeline bool) {
		if len(cur.words) > 0 || len(cur.redirs) > 0 {
			pipeline = append(pipeline, cur)
		}
		cur = segment{}
		if endsPipeline {
			p.pipeline(pipeline, c, depth)
			pipeline = nil
		}
	}
	for _, t := range lex(s) {
		switch t.kind {
		case tWord:
			cur.words = append(cur.words, t.w)
		case tRedir:
			cur.redirs = append(cur.redirs, t)
		case tOp:
			flush(t.op != "|" && t.op != "|&")
		}
	}
	flush(true)
}

func (p *parser) pipeline(segs []segment, c ctx, depth int) {
	var f feed
	for _, s := range segs {
		prog := p.simple(s.words, s.redirs, c, depth, f)
		if fetchers[prog] {
			f.fetcher = prog
		}
		f.prev = prog
	}
}

var (
	skipKeywords   = set("!", "{", "}", "then", "else", "do", "if", "elif", "while", "until", "fi", "done", "esac")
	headerKeywords = set("for", "case", "select", "function", "in")
	shells         = set("bash", "sh", "zsh", "dash", "ksh", "fish")
	fetchers       = set("curl", "wget", "http", "https", "aria2c", "fetch")
)

// simple strips what does not identify a command (keywords, assignments,
// neutral wrappers), follows runners into the command they run, and records
// what is left. It returns the program it recorded, for the pipe after it.
func (p *parser) simple(words []word, redirs []token, c ctx, depth int, f feed) string {
	if p.inv != nil {
		p.substitutions(words, redirs, c, depth)
	}
	for len(words) > 0 {
		w0 := words[0]
		if isAssignment(w0) {
			words = words[1:]
			continue
		}
		if w0.quoted || strings.Contains(w0.lit, substMark) {
			break
		}
		name := w0.lit
		if skipKeywords[name] {
			words = words[1:]
			continue
		}
		if headerKeywords[name] {
			return ""
		}
		base := path.Base(name)
		next := ""
		if len(words) > 1 {
			next = words[1].lit
		}
		switch {
		case base == "sudo" || base == "doas":
			c.sudo = true
			words = skipFlags(words[1:], sudoValueFlags)
			continue
		case base == "timeout":
			words = skipFlags(words[1:], set("-s", "--signal", "-k", "--kill-after"))
			if len(words) > 0 {
				words = words[1:]
			}
			continue
		case base == "nice":
			words = skipFlags(words[1:], set("-n", "--adjustment"))
			continue
		case base == "nohup" || base == "builtin":
			words = words[1:]
			continue
		case base == "time":
			words = skipFlags(words[1:], nil)
			continue
		case base == "stdbuf":
			words = skipFlags(words[1:], set("-i", "-o", "-e"))
			continue
		case base == "exec":
			words = skipFlags(words[1:], set("-a"))
			continue
		case base == "command" && next != "-v" && next != "-V":
			words = skipFlags(words[1:], nil)
			continue
		case base == "env":
			rest := skipFlags(words[1:], set("-u", "--unset", "-C", "--chdir", "-S", "--split-string"))
			for len(rest) > 0 && isAssignment(rest[0]) {
				rest = rest[1:]
			}
			if len(rest) == 0 {
				break
			}
			c.indirect = true
			words = rest
			continue
		case base == "xargs":
			rest := skipFlags(words[1:], xargsValueFlags)
			if len(rest) == 0 {
				break
			}
			c.indirect = true
			words = rest
			continue
		case (base == "uv" || base == "poetry") && next == "run", base == "pnpm" && next == "exec":
			rest := skipFlags(words[2:], uvRunValueFlags)
			if len(rest) == 0 {
				break
			}
			c.indirect = true
			words = rest
			continue
		case shells[base] && depth < maxDepth:
			if script, ok := dashC(words); ok {
				if tag := opaqueTag(script); tag == "fetch" && p.inv == nil {
					return p.emit(opaqueCommand(base, "-c", script, c))
				}
				inner := c
				inner.indirect = true
				p.line(script.lit, inner, depth+1)
				return base
			}
		case base == "eval" && depth < maxDepth:
			return p.eval(words[1:], c, depth)
		}
		break
	}
	if p.inv != nil {
		return p.invoke(words, redirs, c, depth, f)
	}
	if len(words) == 0 {
		if c.sudo {
			return p.emit(finish(&analysis{prog: "sudo", sudo: true}, "sudo", c))
		}
		return ""
	}
	return p.emit(analyze(p, words, redirs, c, depth, f))
}

func (p *parser) eval(args []word, c ctx, depth int) string {
	var raw []string
	opaque := false
	for _, a := range args {
		if len(a.subst) > 0 {
			opaque = true
		}
		raw = append(raw, a.lit)
	}
	joined := word{lit: strings.Join(raw, " ")}
	for _, a := range args {
		joined.subst = append(joined.subst, a.subst...)
	}
	if opaque && p.inv == nil {
		return p.emit(opaqueCommand("eval", "", joined, c))
	}
	inner := c
	inner.indirect = true
	p.line(joined.lit, inner, depth+1)
	return "eval"
}

// opaqueCommand records an interpreter handed code the pattern cannot read,
// such as bash -c "$(curl …)".
func opaqueCommand(prog, flag string, script word, c ctx) Command {
	a := &analysis{prog: prog, sudo: c.sudo}
	tag := opaqueTag(script)
	parts := []string{prog}
	if flag != "" {
		parts = append(parts, flag)
	}
	parts = append(parts, tagged(phScript, tag))
	a.noteTag(tag)
	if tag == "fetch" {
		a.fetchSubst = true
	}
	a.interp = true
	return finish(a, strings.Join(parts, " "), c)
}

func (p *parser) emit(cmd Command) string {
	if cmd.Pattern == "" {
		return ""
	}
	if i, ok := p.index[cmd.Pattern]; ok {
		p.out[i].Indirect = p.out[i].Indirect && cmd.Indirect
		return cmd.Program
	}
	if len(p.out) >= maxCommands {
		return cmd.Program
	}
	p.index[cmd.Pattern] = len(p.out)
	p.out = append(p.out, cmd)
	return cmd.Program
}

// dashC finds the command string of `sh -c '…'`, allowing option clusters such
// as -lc and -ec before it.
func dashC(words []word) (word, bool) {
	for i := 1; i < len(words); i++ {
		w := words[i].lit
		switch {
		case w == "-o" || w == "+o":
			i++
		case strings.HasPrefix(w, "-") && !strings.HasPrefix(w, "--") && strings.Contains(w[1:], "c"):
			if i+1 < len(words) {
				return words[i+1], true
			}
			return word{}, false
		case strings.HasPrefix(w, "-") || strings.HasPrefix(w, "+"):
		default:
			return word{}, false
		}
	}
	return word{}, false
}

func skipFlags(ws []word, valueFlags map[string]bool) []word {
	for len(ws) > 0 {
		w := ws[0].lit
		if ws[0].quoted || len(w) < 2 || w[0] != '-' {
			return ws
		}
		if w == "--" {
			return ws[1:]
		}
		if valueFlags[w] && len(ws) > 1 {
			ws = ws[2:]
			continue
		}
		ws = ws[1:]
	}
	return ws
}

func isAssignment(w word) bool {
	eq := strings.IndexByte(w.lit, '=')
	if eq <= 0 || w.quoteAt > 0 && w.quoteAt-1 <= eq {
		return false
	}
	for i := 0; i < eq; i++ {
		if !isNameByte(w.lit[i], i > 0) {
			return false
		}
	}
	return true
}

// Fit bounds s to MaxLen. A longer string keeps a prefix and a hash of the whole,
// so two long patterns that share the prefix stay distinct and the same long
// pattern always truncates to the same key.
func Fit(s string) string {
	if len(s) <= MaxLen {
		return s
	}
	sum := sha256.Sum256([]byte(s))
	suffix := "…" + hex.EncodeToString(sum[:])[:8]
	cut := MaxLen - len(suffix)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + suffix
}

func set(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}
