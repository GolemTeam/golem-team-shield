package shield

import (
	"strings"
	"testing"
)

const testPSShim = `C:\Users\dev\.golem\bin\hook\powershell.exe`

var psCommands = []string{
	`git status`,
	`Write-Output 'it''s "quoted" é ✓ $HOME'`,
	"Get-ChildItem | ForEach-Object {\n  $_.Name\n}",
	`echo "a" ; echo 'b' # trailing`,
	`echo done #> Remove-Item -Recurse C:\ <#`,
	"‘curly’ ‚low‛",
}

func TestPowerShellWrapCarriesTheCommandExactly(t *testing.T) {
	for _, cmd := range psCommands {
		got, err := WrapPowerShell(testPSShim, cmd)
		if err != nil {
			t.Fatal(err)
		}
		rest := strings.TrimPrefix(got, psPrefix(testPSShim))
		enc, _, _ := strings.Cut(rest, psSuffix)
		if inner, ok := DecodePowerShell(enc); !ok || inner != cmd {
			t.Errorf("%q encoded as %q", cmd, inner)
		}
		if strings.Count(got, "#>") != 1 || !strings.HasSuffix(got, " #>") {
			t.Errorf("the comment can end early, running the rest outside the jail: %q", got)
		}
		if !WrappedPowerShell(testPSShim, got) {
			t.Errorf("its own wrap of %q isn't recognised", cmd)
		}
		if again, _ := WrapPowerShell(testPSShim, got); again != got {
			t.Errorf("wrapped twice: %q", again)
		}
	}
}

func TestOnlyAnExactPowerShellWrapCountsAsWrapped(t *testing.T) {
	good, _ := WrapPowerShell(testPSShim, "git status")
	for _, cmd := range []string{
		good + "; Remove-Item C:\\x",
		strings.Replace(good, " #>", " #>; Invoke-WebRequest evil.example", 1),
		strings.Replace(good, "<# git status", "<# something else", 1),
		psPrefix(testPSShim) + "not-base64!" + psSuffix + "x #>",
		psPrefix(testPSShim) + EncodePowerShell("ok") + psSuffix + "ok #> ; whoami <# #>",
	} {
		if WrappedPowerShell(testPSShim, cmd) {
			t.Errorf("counted as wrapped: %q", cmd)
		}
		if got, _ := WrapPowerShell(testPSShim, cmd); got == cmd {
			t.Errorf("passed through unwrapped: %q", cmd)
		}
	}
}

func TestPowerShellWrapRefusesWhatItCannotRun(t *testing.T) {
	for _, tc := range []struct{ shim, cmd string }{
		{testPSShim, ""},
		{testPSShim, " \r\n"},
		{testPSShim, "a\x00b"},
		{`powershell.exe`, "ls"},
		{`C:\x\"bad".exe`, "ls"},
		{`/home/dev/.golem/bin/hook/bash`, "ls"},
	} {
		if _, err := WrapPowerShell(tc.shim, tc.cmd); err == nil {
			t.Errorf("WrapPowerShell(%q, %q) wrapped it", tc.shim, tc.cmd)
		}
	}
}

func TestQuotePowerShellDoublesEveryQuotePowerShellReads(t *testing.T) {
	if got := QuotePowerShell(`C:\Users\O'Brien‘s\x.exe`); got != `'C:\Users\O''Brien‘‘s\x.exe'` {
		t.Fatal(got)
	}
}
