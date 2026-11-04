package agentposture

import (
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"
)

// parseYAMLSubset reads the YAML agents write for their own configs and
// nothing more: block mappings and sequences, flow [..] and {..}, plain,
// quoted and block (| and >) scalars, and comments. Every value comes back as
// a string, a []any or a map[string]any; nothing in a file can name a type.
// Anchors, aliases, tags, merge keys, directives and tabs are refused rather
// than half-understood, and nesting and size are bounded, so a hostile file
// costs a refusal, not a guess or a blow-up. Only the first document is read.
func parseYAMLSubset(b []byte) (any, error) {
	if !utf8.Valid(b) {
		return nil, errYAML
	}
	var lines []yamlLine
	for n, raw := range strings.Split(strings.TrimPrefix(string(b), "\uFEFF"), "\n") {
		raw = strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(raw)
		switch {
		case trimmed == "---" && len(lines) == 0:
			continue
		case trimmed == "---" || trimmed == "...":
			n = -1
		case strings.HasPrefix(trimmed, "%"):
			return nil, errYAML
		}
		if n < 0 {
			break
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		if strings.HasPrefix(raw[indent:], "\t") {
			return nil, errYAML
		}
		lines = append(lines, yamlLine{indent: indent, text: raw[indent:]})
	}
	p := &yamlParser{lines: lines}
	p.skipBlank()
	if p.i >= len(p.lines) {
		return map[string]any{}, nil
	}
	v, err := p.block(p.lines[p.i].indent, 0)
	if err != nil {
		return nil, err
	}
	if p.skipBlank(); p.i < len(p.lines) {
		return nil, errYAML
	}
	return v, nil
}

var errYAML = errors.New("not the YAML subset agents' configs use")

const (
	yamlMaxDepth = 32
	yamlMaxNodes = 20000
)

type yamlLine struct {
	indent int
	text   string
}

type yamlParser struct {
	lines []yamlLine
	i     int
	nodes int
}

func (p *yamlParser) count() error {
	if p.nodes++; p.nodes > yamlMaxNodes {
		return errYAML
	}
	return nil
}

func (p *yamlParser) skipBlank() {
	for p.i < len(p.lines) {
		t := stripYAMLComment(p.lines[p.i].text)
		if strings.TrimSpace(t) != "" {
			return
		}
		p.i++
	}
}

func (p *yamlParser) block(indent, depth int) (any, error) {
	if depth > yamlMaxDepth {
		return nil, errYAML
	}
	p.skipBlank()
	if p.i >= len(p.lines) {
		return "", nil
	}
	t := stripYAMLComment(p.lines[p.i].text)
	if t == "-" || strings.HasPrefix(t, "- ") {
		return p.sequence(indent, depth)
	}
	return p.mapping(indent, depth)
}

func (p *yamlParser) mapping(indent, depth int) (map[string]any, error) {
	out := map[string]any{}
	for {
		p.skipBlank()
		if p.i >= len(p.lines) || p.lines[p.i].indent < indent {
			return out, nil
		}
		line := p.lines[p.i]
		if line.indent > indent {
			return nil, errYAML
		}
		t := strings.TrimSpace(stripYAMLComment(line.text))
		if t == "-" || strings.HasPrefix(t, "- ") {
			return out, nil
		}
		key, rest, ok := splitYAMLKey(t)
		if !ok || key == "<<" {
			return nil, errYAML
		}
		if _, dup := out[key]; dup {
			return nil, errYAML
		}
		if err := p.count(); err != nil {
			return nil, err
		}
		p.i++
		v, err := p.value(rest, indent, depth)
		if err != nil {
			return nil, err
		}
		out[key] = v
	}
}

func (p *yamlParser) value(rest string, indent, depth int) (any, error) {
	switch {
	case rest == "":
		p.skipBlank()
		if p.i >= len(p.lines) {
			return "", nil
		}
		next := p.lines[p.i]
		nt := stripYAMLComment(next.text)
		if next.indent > indent || next.indent == indent && (nt == "-" || strings.HasPrefix(nt, "- ")) {
			return p.block(next.indent, depth+1)
		}
		return "", nil
	case rest[0] == '|' || rest[0] == '>':
		return p.blockScalar(rest, indent)
	}
	return parseYAMLInline(rest, depth+1)
}

func (p *yamlParser) sequence(indent, depth int) ([]any, error) {
	out := []any{}
	for {
		p.skipBlank()
		if p.i >= len(p.lines) || p.lines[p.i].indent != indent {
			if p.i < len(p.lines) && p.lines[p.i].indent > indent {
				return nil, errYAML
			}
			return out, nil
		}
		t := stripYAMLComment(p.lines[p.i].text)
		if t != "-" && !strings.HasPrefix(t, "- ") {
			return out, nil
		}
		if err := p.count(); err != nil {
			return nil, err
		}
		rest := strings.TrimSpace(strings.TrimPrefix(t, "-"))
		if _, _, isKey := splitYAMLKey(rest); isKey && rest[0] != '[' && rest[0] != '{' && rest[0] != '"' && rest[0] != '\'' {
			// "- key: value" opens a mapping whose keys line up with "key".
			inner := indent + len(t) - len(strings.TrimLeft(strings.TrimPrefix(t, "-"), " "))
			p.lines[p.i] = yamlLine{indent: inner, text: rest}
			m, err := p.mapping(inner, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, m)
			continue
		}
		p.i++
		v, err := p.value(rest, indent, depth)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
}

func (p *yamlParser) blockScalar(header string, indent int) (string, error) {
	folded := header[0] == '>'
	if strings.TrimLeft(header[1:], "+-") != "" {
		return "", errYAML
	}
	var parts []string
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		if strings.TrimSpace(l.text) != "" && l.indent <= indent {
			break
		}
		parts = append(parts, strings.TrimSpace(l.text))
		p.i++
	}
	sep := "\n"
	if folded {
		sep = " "
	}
	return strings.TrimRight(strings.Join(parts, sep), " \n"), nil
}

func splitYAMLKey(t string) (key, rest string, ok bool) {
	inS, inD, nest := false, false, 0
	for i := 0; i < len(t); i++ {
		switch c := t[i]; {
		case c == '\'' && !inD:
			inS = !inS
		case c == '"' && !inS:
			inD = !inD
		case c == '\\' && inD:
			i++
		case !inS && !inD && (c == '[' || c == '{'):
			nest++
		case !inS && !inD && (c == ']' || c == '}'):
			nest--
		case c == ':' && !inS && !inD && nest == 0 && (i+1 == len(t) || t[i+1] == ' '):
			k, err := yamlScalar(strings.TrimSpace(t[:i]))
			if err != nil || k == "" {
				return "", "", false
			}
			return k, strings.TrimSpace(t[i+1:]), true
		}
	}
	return "", "", false
}

func stripYAMLComment(t string) string {
	inS, inD := false, false
	for i := 0; i < len(t); i++ {
		switch c := t[i]; {
		case c == '\'' && !inD:
			inS = !inS
		case c == '"' && !inS:
			inD = !inD
		case c == '\\' && inD:
			i++
		case c == '#' && !inS && !inD && (i == 0 || t[i-1] == ' '):
			return strings.TrimRight(t[:i], " ")
		}
	}
	return t
}

func parseYAMLInline(s string, depth int) (any, error) {
	if depth > yamlMaxDepth {
		return nil, errYAML
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if s[0] == '[' || s[0] == '{' {
		v, rest, err := parseYAMLFlow(s, depth)
		if err != nil || strings.TrimSpace(rest) != "" {
			return nil, errYAML
		}
		return v, nil
	}
	return yamlScalar(s)
}

func parseYAMLFlow(s string, depth int) (any, string, error) {
	if depth > yamlMaxDepth {
		return nil, "", errYAML
	}
	open := s[0]
	closeCh := byte(']')
	if open == '{' {
		closeCh = '}'
	}
	s = strings.TrimSpace(s[1:])
	var list []any
	m := map[string]any{}
	for {
		if s == "" {
			return nil, "", errYAML
		}
		if s[0] == closeCh {
			if open == '[' {
				if list == nil {
					list = []any{}
				}
				return list, s[1:], nil
			}
			return m, s[1:], nil
		}
		item, rest, err := yamlFlowItem(s, depth)
		if err != nil {
			return nil, "", err
		}
		s = strings.TrimSpace(rest)
		if open == '{' {
			ks, ok := item.(string)
			if !ok || s == "" || s[0] != ':' {
				return nil, "", errYAML
			}
			v, rest, err := yamlFlowItem(strings.TrimSpace(s[1:]), depth)
			if err != nil || ks == "<<" {
				return nil, "", errYAML
			}
			m[ks] = v
			s = strings.TrimSpace(rest)
		} else {
			list = append(list, item)
		}
		if s != "" && s[0] == ',' {
			s = strings.TrimSpace(s[1:])
		}
	}
}

func yamlFlowItem(s string, depth int) (any, string, error) {
	if s == "" {
		return nil, "", errYAML
	}
	switch s[0] {
	case '[', '{':
		return parseYAMLFlow(s, depth+1)
	case '"', '\'':
		end := quotedEnd(s)
		if end < 0 {
			return nil, "", errYAML
		}
		v, err := yamlScalar(s[:end+1])
		return v, s[end+1:], err
	}
	end := strings.IndexAny(s, ",]}")
	if c := strings.Index(s, ": "); c >= 0 && (end < 0 || c < end) {
		end = c
	}
	if end < 0 {
		return nil, "", errYAML
	}
	v, err := yamlScalar(strings.TrimSpace(s[:end]))
	return v, s[end:], err
}

func quotedEnd(s string) int {
	q := s[0]
	for i := 1; i < len(s); i++ {
		switch {
		case q == '"' && s[i] == '\\':
			i++
		case s[i] == q && q == '\'' && i+1 < len(s) && s[i+1] == '\'':
			i++
		case s[i] == q:
			return i
		}
	}
	return -1
}

// yamlScalar refuses a plain scalar that would be an anchor, an alias or a
// tag: those are the parts of YAML that make a value something other than
// the text in front of you.
func yamlScalar(s string) (string, error) {
	switch {
	case s == "":
		return "", nil
	case s[0] == '&' || s[0] == '*' || s[0] == '!' || s[0] == '|' || s[0] == '>' || s[0] == '@' || s[0] == '`':
		return "", errYAML
	case s[0] == '\'':
		if len(s) < 2 || s[len(s)-1] != '\'' {
			return "", errYAML
		}
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'"), nil
	case s[0] == '"':
		if len(s) < 2 || s[len(s)-1] != '"' {
			return "", errYAML
		}
		v, err := strconv.Unquote(s)
		if err != nil {
			return "", errYAML
		}
		return v, nil
	}
	if s == "~" || s == "null" || s == "Null" || s == "NULL" {
		return "", nil
	}
	return s, nil
}
