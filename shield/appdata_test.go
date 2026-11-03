//go:build !windows

package shield

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSeatbeltDeniesAppStoresInEveryState(t *testing.T) {
	for _, p := range []Policy{
		{Enforce: true, State: Clean, Grants: AllGrants()},
		{Enforce: true, State: Tainted},
	} {
		out, err := CompileSeatbelt(p, testContext())
		if err != nil {
			t.Fatal(err)
		}
		deny := ruleBlock(out, "(deny file-read* file-write*")
		for _, want := range []string{
			`(regex #"^/Users/dev/Library/Application Support/Google/Chrome[^/]*(/|$)")`,
			`(subpath "/Users/dev/Library/Application Support/Firefox")`,
			`(subpath "/Users/dev/Library/Cookies")`,
			`(subpath "/Users/dev/Library/Application Support/Slack")`,
			`(subpath "/Users/dev/Library/Group Containers/2BUA8C4S2C.com.1password/Library")`,
			`(regex #"\.kdbx$")`,
			`(subpath "/Users/dev/Library/Mail")`,
			`(subpath "/Users/dev/Library/Messages")`,
		} {
			if !strings.Contains(deny, want) {
				t.Errorf("%s: the credential denial lacks %s", p.State, want)
			}
		}
		if strings.Contains(deny, "2BUA8C4S2C.com.1password/t") {
			t.Error("1Password's agent socket is denied as a store")
		}
	}
}

func ruleBlock(profile, verb string) string {
	i := strings.Index(profile, verb)
	if i < 0 {
		return ""
	}
	if j := strings.Index(profile[i:], ")\n("); j >= 0 {
		return profile[i : i+j]
	}
	return profile[i:]
}

func TestLandlockDeniesInstalledAppStoresOnly(t *testing.T) {
	tr := newLLTree(t)
	h := func(p string) string { return filepath.Join(tr.home, p) }
	stores := []string{
		".mozilla/firefox/x.default/cookies.sqlite",
		".config/google-chrome/Default/Cookies",
		".config/Slack/storage/x",
		".password-store/github.gpg",
		".thunderbird/x/prefs.js",
	}
	for _, f := range stores {
		plantFile(t, h(f))
	}
	for _, p := range []Policy{
		{Enforce: true, State: Clean, Grants: AllGrants()},
		{Enforce: true, State: Tainted},
	} {
		j := compileLL(t, p, tr.context(), 7)
		for _, f := range stores {
			if a := access(j, h(f)); a&(llReadFile|llWriteFile) != 0 {
				t.Errorf("%s: %s is readable or writable (%#x)", p.State, f, a)
			}
		}
		if access(j, h(".config/nvim/init.lua"))&llReadFile == 0 {
			t.Errorf("%s: the rest of ~/.config isn't readable", p.State)
		}
	}
	plantFile(t, h(".local/state/x"))
	j := compileLL(t, Policy{Enforce: true, State: Clean, Grants: AllGrants()}, tr.context(), 7)
	if access(j, h(".local/new"))&llMakeDir == 0 {
		t.Error("an app that isn't installed took ~/.local with it")
	}
}
