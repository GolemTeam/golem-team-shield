package agentposture

import "encoding/json"

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
