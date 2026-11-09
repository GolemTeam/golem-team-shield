package agentposture

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/GolemTeam/golem-team-shield/internal/secretpattern"
)

const diffContext = 2

const maxDiffCells = 4 << 20

var (
	jsonPairRE = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"(\s*:\s*)"((?:[^"\\]|\\.)*)"`)
	tomlPairRE = regexp.MustCompile(`^(\s*"?([A-Za-z0-9_.-]+)"?\s*=\s*)("[^"]*"|'[^']*')`)
	quotedRE   = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)
)

const redacted = "<redacted>"

func secretShaped(key, value string) bool {
	if value == "" {
		return false
	}
	if strings.EqualFold(key, "authorization") || literalSecret(key, value) || secretValueRe.MatchString(value) {
		return true
	}
	_, ok := secretpattern.Find(value)
	return ok
}

// redactLine hides every credential-shaped value on a line, context lines
// included: the diff prints those as well as the edited ones.
func redactLine(line string) string {
	line = jsonPairRE.ReplaceAllStringFunc(line, func(m string) string {
		p := jsonPairRE.FindStringSubmatch(m)
		if secretShaped(p[1], p[3]) {
			return `"` + p[1] + `"` + p[2] + `"` + redacted + `"`
		}
		return m
	})
	if p := tomlPairRE.FindStringSubmatch(line); p != nil && secretShaped(p[2], strings.Trim(p[3], `"'`)) {
		line = p[1] + `"` + redacted + `"` + line[len(p[0]):]
	}
	line = quotedRE.ReplaceAllStringFunc(line, func(m string) string {
		if v := m[1 : len(m)-1]; v != redacted && secretShaped("", v) {
			return `"` + redacted + `"`
		}
		return m
	})
	return secretValueRe.ReplaceAllString(line, redacted)
}

type diffOp struct {
	kind byte
	line string
}

func lineDiff(a, b []string) []diffOp {
	n, m := len(a), len(b)
	if n*m > maxDiffCells {
		return nil
	}
	lcs := make([][]int32, n+1)
	for i := range lcs {
		lcs[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var ops []diffOp
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && a[i] == b[j]:
			ops = append(ops, diffOp{' ', a[i]})
			i++
			j++
		case i < n && (j == m || lcs[i+1][j] >= lcs[i][j+1]):
			ops = append(ops, diffOp{'-', a[i]})
			i++
		default:
			ops = append(ops, diffOp{'+', b[j]})
			j++
		}
	}
	return ops
}

func splitLines(b []byte) []string {
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// Diff is the change to the file's contents as a unified diff, with every
// credential-shaped value hidden; "" when only its permissions change.
func (f FileFix) Diff() string {
	if f.Old == nil {
		return ""
	}
	a, b := splitLines(f.Old), splitLines(f.New)
	ops := lineDiff(a, b)
	var out strings.Builder
	fmt.Fprintf(&out, "--- %s\n+++ %s\n", f.Location, f.Location)
	if ops == nil {
		fmt.Fprintf(&out, "(too long to show: %d lines become %d)\n", len(a), len(b))
		return out.String()
	}
	for start := 0; start < len(ops); {
		if ops[start].kind == ' ' {
			start++
			continue
		}
		lo, last := max(start-diffContext, 0), start
		for k := start; k < len(ops) && k-last <= 2*diffContext; k++ {
			if ops[k].kind != ' ' {
				last = k
			}
		}
		hi := min(last+diffContext+1, len(ops))
		oldStart, newStart := 1, 1
		for _, op := range ops[:lo] {
			if op.kind != '+' {
				oldStart++
			}
			if op.kind != '-' {
				newStart++
			}
		}
		oldLen, newLen := 0, 0
		for _, op := range ops[lo:hi] {
			if op.kind != '+' {
				oldLen++
			}
			if op.kind != '-' {
				newLen++
			}
		}
		fmt.Fprintf(&out, "@@ -%d,%d +%d,%d @@\n", oldStart, oldLen, newStart, newLen)
		for _, op := range ops[lo:hi] {
			out.WriteByte(op.kind)
			out.WriteString(redactLine(op.line))
			out.WriteByte('\n')
		}
		start = hi
	}
	return out.String()
}
