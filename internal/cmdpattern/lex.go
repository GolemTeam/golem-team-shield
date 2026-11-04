package cmdpattern

import "strings"

// substMark stands in for a command or process substitution inside a word. Its
// output is unknown until it runs, so nothing may read a program or path out of it.
const substMark = ""

type word struct {
	lit    string // quotes removed, $NAME kept, substitutions replaced by substMark
	quoted bool
	// quoteAt is one past the offset in lit where quoting or an escape began,
	// or 0 for none: FOO="a b" is an assignment, "FOO=x" is a command name.
	quoteAt int
	subst   []string
	vars    []string
}

func (w word) onlySubst() bool { return w.lit == substMark }

func (w *word) markQuote(at int) {
	if w.quoteAt == 0 {
		w.quoteAt = at + 1
	}
}

type tokKind int

const (
	tWord tokKind = iota
	tOp
	tRedir
)

type token struct {
	kind tokKind
	op   string
	w    word // for tRedir: the target, or a heredoc's body
}

// lex never fails: an unterminated quote or substitution runs to the end of the
// input, because the input is often a truncated preview and a pattern of what is
// there beats none.
func lex(s string) []token {
	l := &lexer{s: s, lastNL: strings.LastIndexByte(s, '\n')}
	l.run()
	return l.toks
}

type lexer struct {
	s       string
	i       int
	toks    []token
	pending []int
	lastNL  int
}

func (l *lexer) run() {
	for l.i < len(l.s) {
		c := l.s[l.i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			l.i++
		case c == '\\' && l.peek(1) == '\n':
			l.i += 2
		case c == '\n':
			l.i++
			l.op("\n")
			l.readHeredocBodies()
		case c == '#':
			for l.i < len(l.s) && l.s[l.i] != '\n' {
				l.i++
			}
		case c == ';':
			l.i++
			if l.peek(0) == ';' {
				l.i++
			}
			l.op(";")
		case c == '&':
			switch {
			case l.peek(1) == '&':
				l.i += 2
				l.op("&&")
			case l.peek(1) == '>':
				op := "&>"
				if l.peek(2) == '>' {
					op = "&>>"
				}
				l.i += len(op)
				l.redir(op)
			default:
				l.i++
				l.op("&")
			}
		case c == '|':
			switch l.peek(1) {
			case '|':
				l.i += 2
				l.op("||")
			case '&':
				l.i += 2
				l.op("|&")
			default:
				l.i++
				l.op("|")
			}
		case c == '(' || c == ')':
			l.i++
			l.op(string(c))
		case (c == '<' || c == '>') && l.peek(1) != '(':
			l.redirOp("")
		default:
			w := l.word()
			if !w.quoted && isDigits(w.lit) && (l.peek(0) == '<' || l.peek(0) == '>') && l.peek(1) != '(' {
				l.redirOp(w.lit)
				continue
			}
			l.toks = append(l.toks, token{kind: tWord, w: w})
		}
	}
}

func (l *lexer) peek(off int) byte {
	if l.i+off < len(l.s) {
		return l.s[l.i+off]
	}
	return 0
}

func (l *lexer) op(op string) { l.toks = append(l.toks, token{kind: tOp, op: op}) }

func (l *lexer) redirOp(fd string) {
	op := ">"
	for _, cand := range []string{"<<<", "<<-", "<<", "<>", "<&", "<", ">>", ">&", ">|", ">"} {
		if strings.HasPrefix(l.s[l.i:], cand) {
			op = cand
			break
		}
	}
	l.i += len(op)
	l.redir(fd + op)
}

func (l *lexer) redir(op string) {
	l.skipBlanks()
	if l.i >= len(l.s) || strings.IndexByte(" \t\n;&|()<>", l.s[l.i]) >= 0 {
		l.toks = append(l.toks, token{kind: tRedir, op: op})
		return
	}
	target := l.word()
	if !isHeredoc(op) {
		l.toks = append(l.toks, token{kind: tRedir, op: op, w: target})
		return
	}
	delim := strings.ReplaceAll(target.lit, substMark, "")
	l.toks = append(l.toks, token{kind: tRedir, op: op, w: word{lit: delim, quoted: true}})
	if l.i <= l.lastNL {
		l.pending = append(l.pending, len(l.toks)-1)
		return
	}
	// No newline after the operator: the line was whitespace-collapsed, as the
	// witness's summary_text is, so the body runs to the delimiter as a word.
	l.toks[len(l.toks)-1].w.lit = l.collapsedBody(delim)
}

func (l *lexer) collapsedBody(delim string) string {
	rest := l.s[l.i:]
	for off := 0; delim != "" && off < len(rest); {
		j := strings.Index(rest[off:], delim)
		if j < 0 {
			break
		}
		at := off + j
		end := at + len(delim)
		before := at == 0 || rest[at-1] == ' ' || rest[at-1] == '\t'
		after := end == len(rest) || strings.IndexByte(" \t;&|)", rest[end]) >= 0
		if before && after {
			l.i += end
			return strings.TrimSpace(rest[:at])
		}
		off = at + 1
	}
	l.i = len(l.s)
	return strings.TrimSpace(rest)
}

func (l *lexer) readHeredocBodies() {
	for _, ti := range l.pending {
		tok := &l.toks[ti]
		delim, strip := tok.w.lit, strings.HasSuffix(tok.op, "<<-")
		var body strings.Builder
		for l.i < len(l.s) {
			line, next := l.s[l.i:], len(l.s)
			if end := strings.IndexByte(l.s[l.i:], '\n'); end >= 0 {
				line, next = l.s[l.i:l.i+end], l.i+end+1
			}
			l.i = next
			cmp := strings.TrimRight(line, "\r")
			if strip {
				cmp = strings.TrimLeft(cmp, "\t")
			}
			if cmp == delim {
				break
			}
			body.WriteString(line)
			body.WriteByte('\n')
		}
		tok.w.lit = body.String()
	}
	l.pending = l.pending[:0]
}

func (l *lexer) skipBlanks() {
	for l.i < len(l.s) && (l.s[l.i] == ' ' || l.s[l.i] == '\t') {
		l.i++
	}
}

func (l *lexer) word() word {
	var w word
	var b strings.Builder
	for l.i < len(l.s) {
		c := l.s[l.i]
		switch {
		case c == '\\':
			w.markQuote(b.Len())
			if l.i+1 < len(l.s) && l.s[l.i+1] != '\n' {
				b.WriteByte(l.s[l.i+1])
			}
			l.i = min(l.i+2, len(l.s))
		case c == '\'':
			w.quoted = true
			w.markQuote(b.Len())
			if end := strings.IndexByte(l.s[l.i+1:], '\''); end >= 0 {
				b.WriteString(l.s[l.i+1 : l.i+1+end])
				l.i += end + 2
			} else {
				b.WriteString(l.s[l.i+1:])
				l.i = len(l.s)
			}
		case c == '"':
			w.quoted = true
			w.markQuote(b.Len())
			l.i++
			l.doubleQuoted(&w, &b)
		case c == '$' && l.peek(1) == '\'':
			w.quoted = true
			w.markQuote(b.Len())
			l.i += 2
			l.ansiC(&b)
		case c == '$':
			l.dollar(&w, &b)
		case c == '`':
			w.subst = append(w.subst, l.backtick())
			b.WriteString(substMark)
		case (c == '<' || c == '>') && l.peek(1) == '(' && b.Len() == 0:
			l.i++
			w.subst = append(w.subst, l.parens())
			b.WriteString(substMark)
		case strings.IndexByte(" \t\r\n;&|()<>", c) >= 0:
			w.lit = b.String()
			return w
		default:
			b.WriteByte(c)
			l.i++
		}
	}
	w.lit = b.String()
	return w
}

func (l *lexer) doubleQuoted(w *word, b *strings.Builder) {
	for l.i < len(l.s) {
		switch c := l.s[l.i]; c {
		case '"':
			l.i++
			return
		case '\\':
			switch n := l.peek(1); n {
			case '$', '`', '"', '\\':
				b.WriteByte(n)
				l.i += 2
			case '\n':
				l.i += 2
			default:
				b.WriteByte(c)
				l.i++
			}
		case '$':
			l.dollar(w, b)
		case '`':
			w.subst = append(w.subst, l.backtick())
			b.WriteString(substMark)
		default:
			b.WriteByte(c)
			l.i++
		}
	}
}

func (l *lexer) ansiC(b *strings.Builder) {
	for l.i < len(l.s) {
		c := l.s[l.i]
		if c == '\'' {
			l.i++
			return
		}
		if c == '\\' && l.i+1 < len(l.s) {
			b.WriteByte(l.s[l.i+1])
			l.i += 2
			continue
		}
		b.WriteByte(c)
		l.i++
	}
}

func (l *lexer) dollar(w *word, b *strings.Builder) {
	switch n := l.peek(1); {
	case n == '(':
		l.i++
		w.subst = append(w.subst, l.parens())
		b.WriteString(substMark)
	case n == '{':
		body := l.s[l.i+2:]
		if end := strings.IndexByte(body, '}'); end >= 0 {
			body = body[:end]
			l.i += end + 3
		} else {
			l.i = len(l.s)
		}
		name := strings.TrimLeft(body, "#!")
		k := 0
		for k < len(name) && isNameByte(name[k], k > 0) {
			k++
		}
		if k == 0 {
			w.subst = append(w.subst, body)
			b.WriteString(substMark)
			return
		}
		w.vars = append(w.vars, name[:k])
		b.WriteString("$" + name[:k])
	case isNameByte(n, false):
		k := l.i + 1
		for k < len(l.s) && isNameByte(l.s[k], true) {
			k++
		}
		name := l.s[l.i+1 : k]
		w.vars = append(w.vars, name)
		b.WriteString("$" + name)
		l.i = k
	case n != 0 && strings.IndexByte("0123456789?@#$!*-", n) >= 0:
		b.WriteString("$" + string(n))
		l.i += 2
	default:
		b.WriteByte('$')
		l.i++
	}
}

func (l *lexer) parens() string {
	start := l.i + 1
	depth := 0
	for l.i < len(l.s) {
		switch l.s[l.i] {
		case '\\':
			l.i++
		case '\'':
			end := strings.IndexByte(l.s[l.i+1:], '\'')
			if end < 0 {
				l.i = len(l.s)
				return l.s[min(start, len(l.s)):]
			}
			l.i += end + 1
		case '"':
			for l.i++; l.i < len(l.s) && l.s[l.i] != '"'; l.i++ {
				if l.s[l.i] == '\\' {
					l.i++
				}
			}
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				body := l.s[start:l.i]
				l.i++
				return body
			}
		}
		l.i++
	}
	l.i = len(l.s)
	return l.s[min(start, len(l.s)):]
}

func (l *lexer) backtick() string {
	start := l.i + 1
	for l.i = start; l.i < len(l.s); l.i++ {
		if l.s[l.i] == '\\' {
			l.i++
			continue
		}
		if l.s[l.i] == '`' {
			body := l.s[start:l.i]
			l.i++
			return body
		}
	}
	l.i = len(l.s)
	return l.s[min(start, len(l.s)):]
}

func isHeredoc(op string) bool {
	return strings.HasSuffix(op, "<<-") || (strings.HasSuffix(op, "<<") && !strings.HasSuffix(op, "<<<"))
}

func isNameByte(c byte, notFirst bool) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (notFirst && c >= '0' && c <= '9')
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
