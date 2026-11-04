package shield

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode/utf16"
)

// On Windows the agents run PowerShell, so a hook's rewrite is a PowerShell
// command that runs the hook shim, answering as powershell.exe or pwsh.exe,
// with the agent's command (docs/design-local-shield.md, Windows). The
// command travels as -EncodedCommand: Windows PowerShell 5.1 passes a quoted
// argument to a native program without escaping the double quotes inside it,
// so any other form can reach the shim changed. The person approving the call
// still reads the command, in the block comment after it, which is only for
// them: what runs is what was encoded.

var winSafePathRE = regexp.MustCompile(`^[A-Za-z]:\\[^\x00-\x1f"<>|*?]+\.exe$`)

// WrapPowerShell returns command rewritten to run through shim:
//
//	$LASTEXITCODE = 126; & 'C:\Users\x\.golem\bin\hook\powershell.exe' -NoProfile -NonInteractive -EncodedCommand <base64>; exit $LASTEXITCODE <# <command> #>
//
// The exit status is the shim's, and 126 when it couldn't start. A command
// already wrapped for this shim comes back as it is.
func WrapPowerShell(shim, command string) (string, error) {
	if strings.TrimSpace(command) == "" || strings.ContainsRune(command, 0) || !winSafePathRE.MatchString(shim) {
		return "", ErrNotWrappable
	}
	if WrappedPowerShell(shim, command) {
		return command, nil
	}
	return psPrefix(shim) + EncodePowerShell(command) + psSuffix + psComment(command) + " #>", nil
}

// WrappedPowerShell reports whether command is exactly what WrapPowerShell
// writes for shim and some command, so a command dressed up as one can't skip
// the rewrite.
func WrappedPowerShell(shim, command string) bool {
	rest, ok := strings.CutPrefix(command, psPrefix(shim))
	if !ok {
		return false
	}
	enc, _, ok := strings.Cut(rest, psSuffix)
	if !ok {
		return false
	}
	inner, ok := DecodePowerShell(enc)
	if !ok || strings.TrimSpace(inner) == "" || strings.ContainsRune(inner, 0) {
		return false
	}
	return psPrefix(shim)+enc+psSuffix+psComment(inner)+" #>" == command
}

const psSuffix = "; exit $LASTEXITCODE <# "

func psPrefix(shim string) string {
	return "$LASTEXITCODE = 126; & " + QuotePowerShell(shim) + " -NoProfile -NonInteractive -EncodedCommand "
}

// psComment is command as the block comment shows it: a "#>" inside would end
// the comment early and run the rest in the client's own shell, so it is
// broken up. Only the person reads this; the encoded command is what runs.
func psComment(command string) string {
	return strings.ReplaceAll(command, "#>", "# >")
}

// QuotePowerShell is s as one PowerShell single-quoted string. PowerShell
// takes the curly single quotes as quotes too, so each is doubled like '.
func QuotePowerShell(s string) string {
	var b strings.Builder
	b.WriteByte('\'')
	for _, r := range s {
		switch r {
		case '\'', '\u2018', '\u2019', '\u201a', '\u201b':
			b.WriteRune(r)
		}
		b.WriteRune(r)
	}
	b.WriteByte('\'')
	return b.String()
}

// EncodePowerShell is command as -EncodedCommand takes it: base64 of UTF-16LE.
func EncodePowerShell(command string) string {
	u := utf16.Encode([]rune(command))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// DecodePowerShell is the command an -EncodedCommand argument carries.
func DecodePowerShell(enc string) (string, bool) {
	b, err := base64.StdEncoding.DecodeString(enc)
	if err != nil || len(b)%2 != 0 {
		return "", false
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return string(utf16.Decode(u)), EncodePowerShell(string(utf16.Decode(u))) == enc
}
