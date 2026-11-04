package agentposture

import (
	"encoding/json"
	"regexp"
	"strings"
)

// stripTOMLComment cuts a # comment off a TOML line, leaving a # inside a
// string alone.
func stripTOMLComment(line string) string {
	inBasic, inLiteral := false, false
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case c == '\\' && inBasic:
			i++
		case c == '"' && !inLiteral:
			inBasic = !inBasic
		case c == '\'' && !inBasic:
			inLiteral = !inLiteral
		case c == '#' && !inBasic && !inLiteral:
			return line[:i]
		}
	}
	return line
}

// tomlString is the value of a TOML basic or literal string, and whether v is
// one.
func tomlString(v string) (string, bool) {
	if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
		return v[1 : len(v)-1], true
	}
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		var s string
		if json.Unmarshal([]byte(v), &s) == nil {
			return s, true
		}
		return v[1 : len(v)-1], true
	}
	return "", false
}

var (
	codexTableRE    = regexp.MustCompile(`^\[\s*mcp_servers\.(?:"([^"]+)"|([A-Za-z0-9_-]+))\s*\]$`)
	codexEnvTableRE = regexp.MustCompile(`^\[\s*mcp_servers\.(?:"([^"]+)"|([A-Za-z0-9_-]+))\.env\s*\]$`)
)

// ParseCodexMCPServers reads the [mcp_servers.<name>] tables of a Codex
// config.toml: command, args, url, and the string values of its
// [mcp_servers.<name>.env] subtable. It is not a TOML parser, and needs none of
// the rest of the file.
func ParseCodexMCPServers(s string) map[string]MCPServer {
	out := map[string]MCPServer{}
	current, envOf := "", ""
	lines := strings.Split(s, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(stripTOMLComment(lines[i]))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			current, envOf = "", ""
			if m := codexEnvTableRE.FindStringSubmatch(line); m != nil {
				envOf = m[1] + m[2]
			}
			if m := codexTableRE.FindStringSubmatch(line); m != nil {
				current = m[1] + m[2]
				if _, ok := out[current]; !ok {
					out[current] = MCPServer{}
				}
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if envOf != "" {
			if v, ok := tomlString(value); ok {
				d := out[envOf]
				if d.Env == nil {
					d.Env = map[string]string{}
				}
				d.Env[strings.Trim(key, `"'`)] = v
				out[envOf] = d
			}
			continue
		}
		if current == "" {
			continue
		}
		d := out[current]
		switch key {
		case "command":
			d.Command, _ = tomlString(value)
		case "url":
			d.URL, _ = tomlString(value)
		case "args":
			for strings.Count(value, "[") > strings.Count(value, "]") && i+1 < len(lines) {
				i++
				value += " " + strings.TrimSpace(stripTOMLComment(lines[i]))
			}
			d.Args = tomlStrings(value)
		}
		out[current] = d
	}
	for name, d := range out {
		if d.Command == "" && d.URL == "" {
			delete(out, name)
		}
	}
	return out
}

func tomlStrings(v string) []string {
	v = strings.TrimSpace(v)
	if !strings.HasPrefix(v, "[") || !strings.HasSuffix(v, "]") {
		return nil
	}
	var out []string
	inner := v[1 : len(v)-1]
	for len(inner) > 0 {
		inner = strings.TrimLeft(inner, " \t,")
		if inner == "" {
			break
		}
		quote := inner[0]
		if quote != '"' && quote != '\'' {
			break
		}
		end := 1
		for end < len(inner) && inner[end] != quote {
			if quote == '"' && inner[end] == '\\' {
				end++
			}
			end++
		}
		if end >= len(inner) {
			break
		}
		if s, ok := tomlString(inner[:end+1]); ok {
			out = append(out, s)
		}
		inner = inner[end+1:]
	}
	return out
}
