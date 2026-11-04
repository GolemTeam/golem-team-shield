package cmdpattern

import (
	"math"
	"path"
	"regexp"
	"sort"
	"strings"
)

const (
	phSecret = "‹secret›"
	phIP     = "‹ip›"
	phSHA    = "‹sha›"
	phUUID   = "‹uuid›"
	phN      = "‹n›"
	phPath   = "‹path›"
	phStr    = "‹str›"
	phScript = "‹script›"
	phRemote = "‹remote›"
	phBranch = "‹branch›"
	phPkg    = "‹pkg›"
	phCmd    = "‹cmd›"
)

type role int

const (
	roleNone role = iota
	roleStr
	rolePath
	roleRemote
	roleBranch
	rolePkg
	roleLiteral
	roleMode
	roleHost
	roleScript
	roleRemoteable
)

// analysis is what rendering learned about one command, and all that
// categorize reads.
type analysis struct {
	prog, sub, verb string
	class           PathClass
	fetchRunner     string
	sudo            bool
	interp          bool

	flags    []string
	flagVals map[string][]string
	pos      []string

	fileRedirect   bool
	credHit        bool
	persistMention map[string]bool
	persistWrite   map[string]bool
	dropTag        bool
	fetchSubst     bool
	fetchMention   bool
	remote         bool
	hasExec        bool
}

func analyze(p *parser, words []word, redirs []token, c ctx, depth int, f feed) Command {
	a := &analysis{sudo: c.sudo, flagVals: map[string][]string{}}
	var head []string
	if c.sudo {
		head = append(head, "sudo")
	}
	args := words[1:]
	if prefix, pkg, rest, ok := fetchRunner(words); ok {
		a.prog, a.fetchRunner, args = pkg, prefix, rest
		c.indirect = true
		head = append(head, prefix, pkg)
	} else {
		a.prog, a.class = executable(words[0])
		head = append(head, renderExe(a.prog, a.class))
	}
	a.interp = interpreters[canonical(a.prog)]
	subWord, third, args := splitSub(a.prog, args)
	if subWord != "" {
		a.sub, a.verb = a.prog+" "+subWord, subWord
		head = append(head, subWord)
		if third != "" {
			a.verb += " " + third
			head = append(head, third)
		}
	}
	parts := a.renderArgs(p, args, c, depth)
	parts = append(parts, a.renderRedirs(redirs)...)
	if a.interp && f.fetcher != "" && a.readsStdin() {
		a.fetchSubst = true
		head = append([]string{f.fetcher, "|"}, head...)
	}
	return finish(a, strings.Join(append(head, parts...), " "), c)
}

func finish(a *analysis, text string, c ctx) Command {
	cat, attack := a.categorize()
	return Command{
		Program:   Fit(a.prog),
		Sub:       Fit(a.sub),
		Pattern:   Fit(text),
		PathClass: a.class,
		Category:  cat,
		Attack:    attack,
		Indirect:  c.indirect,
		Sudo:      a.sudo,
	}
}

var (
	flagRe    = regexp.MustCompile(`^--?[A-Za-z0-9][A-Za-z0-9_.-]*$`)
	identRe   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,39}$`)
	subRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,39}$`)
	thirdRe   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)
	progRe    = regexp.MustCompile(`^(@[A-Za-z0-9._-]+/)?[A-Za-z0-9._+\[-][A-Za-z0-9._+\[\]-]{0,63}$`)
	pkgRe     = regexp.MustCompile(`^(@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]{1,100}$`)
	ipRe      = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}(:\d+)?(/\d{1,2})?$|^\[[0-9a-fA-F:]+\](:\d+)?$`)
	uuidRe    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	shaRe     = regexp.MustCompile(`^[0-9a-f]{7,64}$`)
	numRe     = regexp.MustCompile(`^[+-]?v?\d+(\.\d+)*[A-Za-z%]{0,3}$`)
	modeRe    = regexp.MustCompile(`^([0-7]{3,4}|[ugoa]*[-+=][rwxXst]+)$`)
	varRe     = regexp.MustCompile(`^\$[A-Za-z_][A-Za-z0-9_]*$`)
	hostRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)
	remoteRe  = regexp.MustCompile(`^(?:([^@/\s:]+)@)?([A-Za-z0-9][A-Za-z0-9.-]*):(.*)$`)
	schemeRe  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://`)
	fileExtRe = regexp.MustCompile(`^[\w@+-][\w.@+-]*\.[A-Za-z][A-Za-z0-9]{0,9}$`)
	fetchRe   = regexp.MustCompile(`\b(curl|wget)\b`)
	dropRe    = regexp.MustCompile(`(?i)\b(drop\s+(table|database|schema)|truncate\s+table)\b`)
	secretKV  = regexp.MustCompile(`(?i)(^|\s)(authorization|bearer|basic|x-api-key|api[-_]?key|token|password|passwd|secret)\s*[:=]?\s*\S{8,}`)
	credVarRe = regexp.MustCompile(`(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIAL)`)
)

var secretPrefixes = []string{
	"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-", "xoxb-", "xoxp-", "xoxa-", "xoxs-",
	"sk-", "sk_live_", "sk_test_", "rk_live_", "AKIA", "ASIA", "AIza", "ya29.", "npm_", "pypi-",
}

// IsSecret reports whether s looks like a credential: a known token prefix, a
// JWT, a key=value pair naming one, or a random-looking string. It is the test
// the patterns mask ‹secret› by, for callers masking other strings the same way.
func IsSecret(s string) bool { return isSecret(s) }

// HomeNorm spells a path under any user's home directory as ~, so the path
// names no user.
func HomeNorm(s string) string { return homeNorm(s) }

func isSecret(s string) bool {
	if len(s) < 12 {
		return false
	}
	for _, p := range secretPrefixes {
		if strings.HasPrefix(s, p) && len(s) >= len(p)+12 && !strings.ContainsAny(s, " /") {
			return true
		}
	}
	if strings.HasPrefix(s, "eyJ") && strings.Count(s, ".") == 2 {
		return true
	}
	if secretKV.MatchString(s) {
		return true
	}
	return highEntropy(s)
}

// highEntropy flags the random-looking strings that tokens are. Hex is left to
// the sha rule, and anything with a path separator to the path rule, because
// both are far more common in commands than tokens are.
func highEntropy(s string) bool {
	if len(s) < 24 || shaRe.MatchString(strings.ToLower(s)) || uuidRe.MatchString(s) {
		return false
	}
	var upper, lower, digit bool
	counts := map[rune]int{}
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= '0' && r <= '9':
			digit = true
		case r == '+' || r == '=' || r == '_' || r == '-':
		default:
			return false
		}
		counts[r]++
	}
	if !(upper && lower && digit) {
		return false
	}
	h := 0.0
	for _, n := range counts {
		p := float64(n) / float64(len(s))
		h -= p * math.Log2(p)
	}
	return h >= 4.0
}

func maskURL(s string) (string, bool) {
	if !schemeRe.MatchString(s) {
		return "", false
	}
	scheme, rest, _ := strings.Cut(s, "://")
	end := strings.IndexAny(rest, "/?#")
	authority, tail := rest, ""
	if end >= 0 {
		authority, tail = rest[:end], rest[end:]
	}
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		authority = authority[at+1:]
	}
	host := authority
	switch {
	case host == "":
	case ipRe.MatchString(host):
		host = phIP
	case !hostRe.MatchString(strings.Split(host, ":")[0]):
		host = phStr
	}
	out := strings.ToLower(scheme) + "://" + host
	if tail != "" && tail != "/" {
		out += "/" + phPath
	}
	return out, true
}

var tmpPrefixes = []string{"/tmp/", "/private/tmp/", "/var/tmp/", "/var/folders/", "/private/var/folders/", "/dev/shm/", "$TMPDIR/"}

// homeNorm spells every way of naming the home directory as ~, so that one path
// has one pattern whoever's machine it ran on.
func homeNorm(s string) string {
	switch {
	case s == "$HOME" || s == "~":
		return "~"
	case strings.HasPrefix(s, "$HOME/"):
		return "~" + s[len("$HOME"):]
	case strings.HasPrefix(s, "/root/") || s == "/root":
		return "~" + s[len("/root"):]
	}
	for _, root := range []string{"/Users/", "/home/"} {
		if rest, ok := strings.CutPrefix(s, root); ok && rest != "" {
			if slash := strings.IndexByte(rest, '/'); slash >= 0 {
				return "~" + rest[slash:]
			}
			return "~"
		}
	}
	return s
}

func executable(w word) (string, PathClass) {
	if w.onlySubst() {
		return phScript, OnPath
	}
	if strings.Contains(w.lit, substMark) {
		return phCmd, OnPath
	}
	if varRe.MatchString(w.lit) {
		return w.lit, OnPath
	}
	n := homeNorm(w.lit)
	class := OnPath
	switch {
	case hasAnyPrefix(n, tmpPrefixes):
		class = Tmp
	case strings.HasPrefix(n, "~"):
		class = Home
	case strings.HasPrefix(n, "/"):
		class = System
	case strings.Contains(n, "/"):
		class = Repo
	}
	base := path.Base(n)
	if !progRe.MatchString(base) || strings.HasPrefix(base, "@") {
		return phCmd, class
	}
	return base, class
}

func renderExe(prog string, class PathClass) string {
	switch class {
	case Home:
		return "‹home›/" + prog
	case Repo:
		return "‹repo›/" + prog
	case Tmp:
		return "‹tmp›/" + prog
	}
	return prog
}

// fetchRunner recognises runners that download a package and run it. The
// package, not the runner, is the program, and the runner stays in the pattern
// because fetching is what makes it an install.
func fetchRunner(words []word) (prefix, pkg string, rest []word, ok bool) {
	if len(words) < 2 || words[0].quoted {
		return "", "", nil, false
	}
	base := path.Base(words[0].lit)
	next := words[1].lit
	switch {
	case base == "npx" || base == "bunx" || base == "uvx":
		prefix, rest = base, words[1:]
	case (base == "pnpm" || base == "yarn") && next == "dlx", base == "npm" && next == "exec", base == "pipx" && next == "run":
		prefix, rest = base+" "+next, words[2:]
	case base == "uv" && next == "tool" && len(words) > 2 && words[2].lit == "run":
		prefix, rest = "uv tool run", words[3:]
	default:
		return "", "", nil, false
	}
	rest = skipFlags(rest, set("-p", "--package", "-c", "--call", "--from", "--with", "--python", "--spec"))
	if len(rest) == 0 || rest[0].quoted {
		return "", "", nil, false
	}
	pkg = pkgName(rest[0].lit)
	if pkg == "" {
		return "", "", nil, false
	}
	return prefix, pkg, rest[1:], true
}

func pkgName(spec string) string {
	name := spec
	if strings.HasPrefix(name, "@") {
		if slash := strings.IndexByte(name, '/'); slash > 0 {
			if at := strings.IndexByte(name[slash:], '@'); at > 0 {
				name = name[:slash+at]
			}
		}
	} else if at := strings.IndexAny(name, "@=<>~!["); at > 0 {
		name = name[:at]
	}
	if !pkgRe.MatchString(name) {
		return ""
	}
	return name
}

func splitSub(prog string, args []word) (sub, third string, rest []word) {
	if !subPrograms[prog] {
		return "", "", args
	}
	gv := globalValueFlags[prog]
	for i := 0; i < len(args); i++ {
		w := args[i]
		if w.quoted || strings.Contains(w.lit, substMark) {
			return "", "", args
		}
		if strings.HasPrefix(w.lit, "-") {
			if gv[w.lit] {
				i++
			}
			continue
		}
		if !subRe.MatchString(w.lit) || numRe.MatchString(w.lit) || strings.Contains(w.lit, "=") {
			return "", "", args
		}
		sub = w.lit
		rest = append(append([]word{}, args[:i]...), args[i+1:]...)
		if allow := thirdLevel[prog]; (allow["*"] || allow[sub]) && i < len(rest) {
			if n := rest[i]; !n.quoted && thirdRe.MatchString(n.lit) {
				third = n.lit
				rest = append(rest[:i:i], rest[i+1:]...)
			}
		}
		return sub, third, rest
	}
	return "", "", args
}

func isFlagWord(w word) bool {
	return !w.quoted && len(w.lit) >= 2 && w.lit[0] == '-' && !strings.Contains(w.lit, substMark)
}

func (a *analysis) renderArgs(p *parser, args []word, c ctx, depth int) []string {
	vf := valueFlags[canonical(a.prog)]
	generic := genericValueFlags[a.prog]
	var parts []string
	pos := 0
	afterDD := false
	prevPos := ""
	for i := 0; i < len(args); i++ {
		w := args[i]
		if afterDD || !isFlagWord(w) {
			a.pos = append(a.pos, w.lit)
			rendered := w.lit
			if !afterDD || !isFlagWord(w) || !flagRe.MatchString(w.lit) {
				rendered = a.maskValue(w, a.role(pos, afterDD))
			}
			pos++
			// A run of one placeholder collapses, so `rm a b c` and `rm a` share
			// a pattern: the count of arguments is the least useful thing about them.
			if rendered == prevPos && strings.HasPrefix(rendered, "‹") {
				continue
			}
			parts = append(parts, rendered)
			prevPos = rendered
			continue
		}
		name := w.lit
		prevPos = ""
		if name == "--" {
			afterDD = true
			parts = append(parts, "--")
			continue
		}
		if a.prog == "find" && findExec[name] {
			end := i + 1
			for end < len(args) && args[end].lit != ";" && args[end].lit != "+" {
				end++
			}
			a.hasExec = true
			a.flags = append(a.flags, name)
			parts = append(parts, name, phCmd)
			if depth < maxDepth && end > i+1 {
				inner := c
				inner.indirect = true
				p.simple(args[i+1:end], nil, inner, depth+1, feed{})
			}
			i = end
			continue
		}
		if k, v, ok := strings.Cut(name, "="); ok && flagRe.MatchString(k) {
			a.noteFlag(k, v)
			parts = append(parts, k+"="+a.maskFlagValue(k, word{lit: v, quoted: w.quoted, subst: w.subst, vars: w.vars}))
			continue
		}
		if !strings.HasPrefix(name, "--") && len(name) > 2 && vf[name[:2]] {
			a.noteFlag(name[:2], name[2:])
			parts = append(parts, name[:2]+a.maskFlagValue(name[:2], word{lit: name[2:], vars: w.vars}))
			continue
		}
		if isDigits(name[1:]) {
			a.flags = append(a.flags, "-N")
			parts = append(parts, "-"+phN)
			continue
		}
		if !flagRe.MatchString(name) {
			parts = append(parts, phStr)
			continue
		}
		if isSecret(name) {
			parts = append(parts, phSecret)
			continue
		}
		a.flags = append(a.flags, name)
		parts = append(parts, name)
		takes := vf[name] || (generic && strings.HasPrefix(name, "--"))
		if takes && i+1 < len(args) && !(generic && !vf[name] && isFlagWord(args[i+1])) {
			i++
			a.noteFlag(name, args[i].lit)
			a.flags = a.flags[:len(a.flags)-1]
			parts = append(parts, a.maskFlagValue(name, args[i]))
		}
	}
	return parts
}

func (a *analysis) noteFlag(name, val string) {
	a.flags = append(a.flags, name)
	a.flagVals[name] = append(a.flagVals[name], val)
}

func (a *analysis) hasFlag(names ...string) bool {
	for _, f := range a.flags {
		for _, n := range names {
			if f == n {
				return true
			}
		}
	}
	return false
}

// hasShortFlag reports whether any single-dash cluster carries letter, so that
// -rf, -fr and -r -f all read as recursive.
func (a *analysis) hasShortFlag(letter byte) bool {
	for _, f := range a.flags {
		if len(f) >= 2 && f[0] == '-' && f[1] != '-' && strings.IndexByte(f[1:], letter) >= 0 {
			return true
		}
	}
	return false
}

func (a *analysis) maskFlagValue(flag string, w word) string {
	lower := strings.ToLower(flag)
	if w.lit != "" && (strings.Contains(lower, "token") || strings.Contains(lower, "passw") || strings.Contains(lower, "secret") ||
		strings.Contains(lower, "api-key") || strings.Contains(lower, "apikey") || strings.Contains(lower, "api_key") ||
		secretValueFlags[canonical(a.prog)][flag]) {
		return phSecret
	}
	if literalValueFlags[canonical(a.prog)][flag] && !w.quoted && identRe.MatchString(w.lit) {
		return w.lit
	}
	r := roleNone
	switch {
	case codeFlags[flag] && a.executesStrings():
		r = roleScript
	case pathValueFlags[flag] || shortPathFlags[canonical(a.prog)][flag]:
		r = rolePath
	}
	return a.maskValue(w, r)
}

func (a *analysis) executesStrings() bool {
	c := canonical(a.prog)
	return interpreters[c] || sqlClients[c]
}

func (a *analysis) role(pos int, afterDD bool) role {
	c := canonical(a.prog)
	switch {
	case a.prog == "git":
		switch a.verb {
		case "push", "pull", "fetch":
			if pos == 0 {
				return roleRemote
			}
			return roleBranch
		case "checkout", "switch", "merge", "rebase", "cherry-pick", "revert", "reset", "tag", "branch":
			if afterDD {
				return rolePath
			}
			return roleBranch
		case "add", "rm", "mv", "restore", "blame", "ls-files":
			return rolePath
		case "clone":
			if pos == 0 {
				return roleRemoteable
			}
			return rolePath
		case "remote add":
			if pos == 0 {
				return roleLiteral
			}
			return roleRemoteable
		}
	case searchers[c]:
		if pos == 0 && !a.hasFlag("-e", "-f", "--regexp", "--file") {
			return roleStr
		}
		return rolePath
	case c == "chmod" || c == "chown" || c == "chgrp":
		if pos == 0 {
			return roleMode
		}
		return rolePath
	case fileArgs[c]:
		return rolePath
	case a.interp:
		if pos == 0 {
			return rolePath
		}
	case installVerb(a.prog, a.verb):
		return rolePkg
	case c == "make":
		return roleLiteral
	case c == "ssh":
		if pos == 0 {
			return roleHost
		}
		return roleScript
	case c == "scp" || c == "rsync" || c == "sftp":
		return roleRemoteable
	case sqlClients[c]:
		return roleScript
	}
	return roleNone
}

func (a *analysis) maskValue(w word, r role) string {
	if w.onlySubst() || strings.Contains(w.lit, substMark) {
		tag := a.noteTag(opaqueTag(w))
		if tag == "fetch" {
			a.fetchMention = true
		}
		if w.onlySubst() {
			return tagged(phScript, tag)
		}
		return tagged(phStr, tag)
	}
	s := w.lit
	switch s {
	case "":
		return phStr
	case "-", "{}", ".", "..", "~", "/":
		return s
	}
	if isSecret(s) {
		return phSecret
	}
	if u, ok := maskURL(s); ok {
		return u
	}
	n := homeNorm(s)
	if rendered, kind, ok := sensitivePath(n); ok {
		a.noteSensitive(kind, false)
		return rendered
	}
	for _, v := range w.vars {
		if credVarRe.MatchString(strings.ToUpper(v)) {
			a.credHit = true
		}
	}
	switch r {
	case roleRemote:
		return phRemote
	case roleBranch:
		if strings.HasPrefix(s, "+") {
			return "+" + phBranch
		}
		return phBranch
	case rolePkg:
		return phPkg
	case roleLiteral:
		if !w.quoted && identRe.MatchString(s) {
			return s
		}
	case roleMode:
		if modeRe.MatchString(s) {
			return s
		}
		return phStr
	case roleHost:
		return a.maskHost(s)
	case roleScript:
		return tagged(phScript, a.noteTag(textTag(s)))
	case roleRemoteable:
		if m := remoteRe.FindStringSubmatch(s); m != nil && !strings.Contains(m[2], "/") && len(m[2]) > 1 {
			a.remote = true
			user := ""
			if m[1] != "" {
				user = phStr + "@"
			}
			if m[1] == "git" {
				user = "git@"
			}
			host := m[2]
			if ipRe.MatchString(host) {
				host = phIP
			}
			return user + host + ":" + phPath
		}
		return phPath
	}
	if varRe.MatchString(s) {
		if credVarRe.MatchString(strings.ToUpper(s)) {
			a.credHit = true
		}
		return s
	}
	switch {
	case ipRe.MatchString(s):
		return phIP
	case uuidRe.MatchString(s):
		return phUUID
	case shaRe.MatchString(s) && strings.ContainsAny(s, "0123456789") && strings.ContainsAny(s, "abcdef"):
		return phSHA
	case numRe.MatchString(s):
		return phN
	case r == roleStr:
		return phStr
	case r == rolePath || looksLikePath(n):
		return phPath
	}
	return phStr
}

func (a *analysis) maskHost(s string) string {
	user := ""
	if at := strings.LastIndexByte(s, '@'); at >= 0 {
		user, s = phStr+"@", s[at+1:]
	}
	switch {
	case ipRe.MatchString(s):
		return user + phIP
	case hostRe.MatchString(s):
		a.remote = true
		return user + s
	}
	return user + phStr
}

func looksLikePath(s string) bool {
	return strings.ContainsAny(s, "/*?") || strings.HasPrefix(s, "~") || strings.HasPrefix(s, ".") || fileExtRe.MatchString(s)
}

func (a *analysis) renderRedirs(redirs []token) []string {
	var parts []string
	for _, r := range redirs {
		op, t := r.op, r.w
		switch {
		case isHeredoc(op):
			tag := ""
			if a.executesStrings() || a.prog == "cat" || a.prog == "tee" {
				tag = a.noteTag(textTag(t.lit))
			}
			parts = append(parts, "<<"+tagged(phScript, tag))
		case strings.HasSuffix(op, "<<<"):
			r := roleStr
			if a.executesStrings() {
				r = roleScript
			}
			parts = append(parts, "<<<"+a.maskValue(t, r))
		case (strings.HasSuffix(op, ">&") || strings.HasSuffix(op, "<&")) && (isDigits(t.lit) || t.lit == "-" || t.lit == ""):
		case t.lit == "/dev/null" || t.lit == "/dev/stdout" || t.lit == "/dev/stderr" || t.lit == "/dev/tty":
		case strings.Contains(op, ">"):
			a.fileRedirect = true
			if _, kind, ok := sensitivePath(homeNorm(t.lit)); ok {
				a.noteSensitive(kind, true)
			}
			parts = append(parts, op+a.maskValue(t, rolePath))
		default:
			parts = append(parts, op+a.maskValue(t, rolePath))
		}
	}
	return parts
}

func (a *analysis) readsStdin() bool {
	if a.hasFlag("-c", "-e", "--eval", "-m", "-p", "--print", "--command") {
		return false
	}
	if shells[a.prog] && a.hasShortFlag('s') {
		return true
	}
	return len(a.pos) == 0 || a.pos[0] == "-"
}

func tagged(ph, tag string) string {
	if tag == "" {
		return ph
	}
	return strings.TrimSuffix(ph, "›") + ":" + tag + "›"
}

type sensitiveRoot struct {
	root string
	kind string
}

var sensitiveRoots = []sensitiveRoot{
	{"~/.ssh", kindCred}, {"~/.aws", kindCred}, {"~/.gnupg", kindCred}, {"~/.netrc", kindCred},
	{"~/.config/gh", kindCred}, {"~/.config/gcloud", kindCred}, {"~/.docker/config.json", kindCred},
	{"~/.kube", kindCred}, {"~/.npmrc", kindCred}, {"~/.pypirc", kindCred}, {"~/.git-credentials", kindCred},
	{"~/Library/Keychains", kindCred}, {"/etc/shadow", kindCred}, {"/etc/sudoers", kindCred},
	{"/etc/master.passwd", kindCred},
	{"~/.zshrc", kindRC}, {"~/.zshenv", kindRC}, {"~/.zprofile", kindRC}, {"~/.zlogin", kindRC},
	{"~/.bashrc", kindRC}, {"~/.bash_profile", kindRC}, {"~/.bash_login", kindRC}, {"~/.profile", kindRC},
	{"~/.config/fish", kindRC}, {"/etc/profile", kindRC}, {"/etc/zshrc", kindRC}, {"/etc/bashrc", kindRC},
	{"~/Library/LaunchAgents", kindLaunch}, {"/Library/LaunchAgents", kindLaunch}, {"/Library/LaunchDaemons", kindLaunch},
	{"/etc/crontab", kindCron}, {"/etc/cron.d", kindCron}, {"/var/spool/cron", kindCron},
}

const (
	kindCred     = "cred"
	kindRC       = "rc"
	kindLaunch   = "launch"
	kindCron     = "cron"
	kindGitHooks = "githooks"
)

var keyFiles = set("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", ".netrc", ".git-credentials", ".env")

// sensitivePath renders the paths a pattern must keep readable: the roots whose
// mere appearance changes a command's category. What lies under the root is
// still masked.
func sensitivePath(p string) (string, string, bool) {
	for _, r := range sensitiveRoots {
		if p == r.root {
			return r.root, r.kind, true
		}
		if strings.HasPrefix(p, r.root+"/") {
			return r.root + "/" + phPath, r.kind, true
		}
	}
	if i := strings.Index(p, ".git/hooks"); i >= 0 && (i == 0 || p[i-1] == '/') {
		return ".git/hooks/" + phPath, kindGitHooks, true
	}
	base := path.Base(p)
	envFile := strings.HasPrefix(base, ".env.") && !hasAnySuffix(base, ".example", ".sample", ".template", ".dist")
	if keyFiles[base] || envFile {
		if base == p {
			return base, kindCred, true
		}
		return phPath + "/" + base, kindCred, true
	}
	return "", "", false
}

var textTags = []struct{ needle, tag string }{
	{".ssh/", "~/.ssh"}, {"~/.ssh", "~/.ssh"}, {".aws/credentials", "~/.aws"}, {"~/.aws", "~/.aws"},
	{".netrc", ".netrc"}, {".gnupg", "~/.gnupg"}, {".git-credentials", ".git-credentials"},
	{"id_rsa", "id_rsa"}, {"id_ed25519", "id_ed25519"}, {"/etc/shadow", "/etc/shadow"},
	{".zshrc", "~/.zshrc"}, {".bashrc", "~/.bashrc"}, {".bash_profile", "~/.bash_profile"},
	{"LaunchAgents", "LaunchAgents"}, {"crontab", "crontab"},
}

var tagKinds = map[string]string{
	"~/.ssh": kindCred, "~/.aws": kindCred, ".netrc": kindCred, "~/.gnupg": kindCred, ".git-credentials": kindCred,
	"id_rsa": kindCred, "id_ed25519": kindCred, "/etc/shadow": kindCred,
	"~/.zshrc": kindRC, "~/.bashrc": kindRC, "~/.bash_profile": kindRC, "LaunchAgents": kindLaunch, "crontab": kindCron,
}

// textTag names the one thing in code the pattern cannot show that would change
// its category. The order is fixed so a string with two of them always gets the
// same tag.
func textTag(s string) string {
	if fetchRe.MatchString(s) {
		return "fetch"
	}
	for _, t := range textTags {
		if strings.Contains(s, t.needle) {
			return t.tag
		}
	}
	if dropRe.MatchString(s) {
		return "DROP"
	}
	return ""
}

func opaqueTag(w word) string { return textTag(strings.Join(w.subst, " ")) }

func (a *analysis) noteTag(tag string) string {
	switch {
	case tag == "":
	case tag == "DROP":
		a.dropTag = true
	case tag == "fetch":
		a.fetchMention = true
	default:
		a.noteSensitive(tagKinds[tag], false)
	}
	return tag
}

func (a *analysis) noteSensitive(kind string, write bool) {
	if kind == kindCred {
		a.credHit = true
		return
	}
	if a.persistMention == nil {
		a.persistMention, a.persistWrite = map[string]bool{}, map[string]bool{}
	}
	a.persistMention[kind] = true
	if write {
		a.persistWrite[kind] = true
	}
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func hasAnySuffix(s string, suffixes ...string) bool {
	for _, x := range suffixes {
		if strings.HasSuffix(s, x) {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
