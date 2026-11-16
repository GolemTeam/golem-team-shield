package agentposture

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type fakeProcesses struct {
	alive   map[int]bool
	environ map[int][]string
	asked   []int
}

func (f *fakeProcesses) Alive(pid int) bool { return f.alive[pid] }

func (f *fakeProcesses) Environ(pid int) ([]string, bool) {
	f.asked = append(f.asked, pid)
	env, ok := f.environ[pid]
	return env, ok
}

func daemonOn(shell string) *fakeProcesses {
	return &fakeProcesses{
		alive:   map[int]bool{4242: true},
		environ: map[int][]string{4242: {"HOME=/Users/x", "SHELL=" + shell, "SAND_LOCAL_EXEC_GENERATION=7"}},
	}
}

func grokBotEnv(t *testing.T, settings string, procs Processes) Env {
	t.Helper()
	env := postureTestEnv(t)
	env.GOOS = "darwin"
	env.Processes = procs
	if settings != "" {
		writePostureFile(t, filepath.Join(env.Home, ".grokbot", "settings.json"), settings)
	}
	writePostureFile(t, filepath.Join(env.Home, ".grokbot", "local-exec-daemon.json"), `{"pid":4242,"startedAt":1763000000000}`)
	return env
}

func grokBotChecks(items []Item) map[string]Item {
	out := map[string]Item{}
	for _, it := range items {
		if it.Client == grokBotClient {
			out[it.Check] = it
		}
	}
	return out
}

func checkNames(m map[string]Item) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func TestGrokBotSettingsAsTheAppWritesThem(t *testing.T) {
	env := grokBotEnv(t, `{
		"version": 1,
		"localToolPermission": "always",
		"localEgressAllowed": true,
		"egressTunnelEnabled": true,
		"egressTunnelCommittedBoxUrls": ["https://pod.cursorvm.com"],
		"webauthnProxyEnabled": true,
		"messagesEnabled": true,
		"messagesReadEnabled": true,
		"messagesSendEnabled": true,
		"macMailSendEnabled": false
	}`, daemonOn("/bin/zsh"))
	writePostureFile(t, filepath.Join(env.Home, ".grokbot", "local-computer-use-gate.json"), `{"isOn":true}`)

	got := grokBotChecks(Scan(env))
	want := map[string]struct{ sev, setting, value, file string }{
		"local_always":        {Dangerous, "localToolPermission", "always", "settings.json"},
		"local_unwrapped":     {Dangerous, "SHELL", "zsh", "local-exec-daemon.json"},
		"egress_through_host": {Suspicious, "egressTunnelEnabled", "true", "settings.json"},
		"messages_send":       {Suspicious, "messagesSendEnabled", "true", "settings.json"},
		"computer_use":        {Suspicious, "isOn", "true", "local-computer-use-gate.json"},
		"security_key_proxy":  {Info, "webauthnProxyEnabled", "true", "settings.json"},
	}
	var wantNames []string
	for c := range want {
		wantNames = append(wantNames, c)
	}
	slices.Sort(wantNames)
	if !slices.Equal(checkNames(got), wantNames) {
		t.Fatalf("checks = %v, want %v", checkNames(got), wantNames)
	}
	for check, w := range want {
		it := got[check]
		if it.Severity != w.sev || it.Setting != w.setting || it.Value != w.value ||
			it.Location != "~/.grokbot/"+w.file || it.Scope != "user" {
			t.Errorf("%s = %+v", check, it)
		}
	}
	if got["computer_use"].Area != AreaPermissions || got["local_unwrapped"].Area != AreaRunModes {
		t.Errorf("areas: computer_use %q, local_unwrapped %q", got["computer_use"].Area, got["local_unwrapped"].Area)
	}
}

func TestGrokBotSettingsThatAreOffAreNoFinding(t *testing.T) {
	procs := daemonOn("/bin/zsh")
	env := grokBotEnv(t, `{
		"localToolPermission": "never",
		"egressTunnelEnabled": false,
		"webauthnProxyEnabled": false,
		"messagesEnabled": false,
		"messagesSendEnabled": true
	}`, procs)
	writePostureFile(t, filepath.Join(env.Home, ".grokbot", "local-computer-use-gate.json"), `{"isOn":false}`)
	if got := grokBotChecks(Scan(env)); len(got) != 0 {
		t.Errorf("findings %v", checkNames(got))
	}
	if len(procs.asked) != 0 {
		t.Error("the daemon was read with local execution off")
	}
}

func TestGrokBotAskIsInfoAndStillChecksTheShell(t *testing.T) {
	got := grokBotChecks(Scan(grokBotEnv(t, `{"localToolPermission":"ask"}`, daemonOn("/opt/homebrew/bin/fish"))))
	if it := got["local_ask"]; it.Severity != Info || it.Value != "ask" {
		t.Errorf("local_ask = %+v", it)
	}
	if _, ok := got["local_always"]; ok {
		t.Error("ask reported as always")
	}
	if it := got["local_unwrapped"]; it.Severity != Dangerous || it.Value != "fish" {
		t.Errorf("local_unwrapped = %+v", it)
	}
}

func TestGrokBotDaemonOnTheShimIsNotUnwrapped(t *testing.T) {
	for _, name := range []string{"golem-zsh", "golem-bash"} {
		procs := &fakeProcesses{}
		env := grokBotEnv(t, `{"localToolPermission":"always"}`, procs)
		*procs = *daemonOn(filepath.Join(env.Home, ".golem", "bin", name))
		got := grokBotChecks(Scan(env))
		if _, ok := got["local_unwrapped"]; ok {
			t.Errorf("%s: reported unwrapped", name)
		}
		if _, ok := got["local_always"]; !ok {
			t.Errorf("%s: the shim hid local_always", name)
		}
	}
	for shell, value := range map[string]string{
		"":                           "unset",
		"/Users/x/bin/golem-zsh-old": "other",
		"/Users/x/golem-zsh/zsh":     "zsh",
		"/tmp/scratch/bin/golem-zsh": "other",
	} {
		got := grokBotChecks(Scan(grokBotEnv(t, `{"localToolPermission":"always"}`, daemonOn(shell))))
		if it := got["local_unwrapped"]; it.Value != value {
			t.Errorf("SHELL %q: local_unwrapped = %+v, want value %q", shell, it, value)
		}
	}
}

func TestGrokBotUnwrappedNeedsALiveReadableDaemon(t *testing.T) {
	daemonFile := func(env Env) string { return filepath.Join(env.Home, ".grokbot", "local-exec-daemon.json") }
	cases := map[string]func(env Env) Env{
		"no daemon file": func(env Env) Env {
			if err := os.Remove(daemonFile(env)); err != nil {
				t.Fatal(err)
			}
			return env
		},
		"empty daemon file": func(env Env) Env {
			writePostureFile(t, daemonFile(env), ``)
			return env
		},
		"malformed daemon file": func(env Env) Env {
			writePostureFile(t, daemonFile(env), `{"pid":`)
			return env
		},
		"no pid": func(env Env) Env {
			writePostureFile(t, daemonFile(env), `{"startedAt":1}`)
			return env
		},
		"dead": func(env Env) Env {
			env.Processes = &fakeProcesses{environ: daemonOn("/bin/zsh").environ}
			return env
		},
		"environment unreadable": func(env Env) Env {
			env.Processes = &fakeProcesses{alive: map[int]bool{4242: true}}
			return env
		},
		"pid now another program's": func(env Env) Env {
			env.Processes = &fakeProcesses{alive: map[int]bool{4242: true},
				environ: map[int][]string{4242: {"SHELL=/bin/zsh"}}}
			return env
		},
		"no process reader": func(env Env) Env {
			env.Processes = nil
			return env
		},
	}
	for name, mod := range cases {
		env := mod(grokBotEnv(t, `{"localToolPermission":"always"}`, daemonOn("/bin/zsh")))
		got := grokBotChecks(Scan(env))
		if _, ok := got["local_unwrapped"]; ok {
			t.Errorf("%s: reported unwrapped", name)
		}
		if _, ok := got["local_always"]; !ok {
			t.Errorf("%s: lost local_always", name)
		}
	}
}

func TestGrokBotFilesMissingOrMalformedAreNoFinding(t *testing.T) {
	for name, body := range map[string]string{
		"missing":       "",
		"malformed":     `{"localToolPermission": "always"`,
		"not an object": `["always"]`,
		"wrong types":   `{"localToolPermission": true, "egressTunnelEnabled": "true", "messagesEnabled": 1, "messagesSendEnabled": true, "webauthnProxyEnabled": "yes"}`,
		"unknown keys":  `{"localToolPermission": "sometimes", "futureKey": {"a": 1}}`,
	} {
		env := grokBotEnv(t, body, daemonOn("/bin/zsh"))
		writePostureFile(t, filepath.Join(env.Home, ".grokbot", "local-computer-use-gate.json"), `{"isOn":`)
		if got := grokBotChecks(Scan(env)); len(got) != 0 {
			t.Errorf("%s: findings %v", name, checkNames(got))
		}
	}
}

func TestGrokBotNeverOpensTheSealedFiles(t *testing.T) {
	env := grokBotEnv(t, `{"localToolPermission":"always","egressTunnelEnabled":true}`, daemonOn("/bin/zsh"))
	for _, f := range []string{"local-exec-daemon-credential.json", "local-exec-daemon-connection.json", "local-exec-supervisor.json"} {
		writePostureFile(t, filepath.Join(env.Home, ".grokbot", f), `{"localToolPermission":"always"}`)
	}
	writePostureFile(t, filepath.Join(env.Home, "Library", "Application Support", "Grok Bot", "sand-secrets.json"), `{}`)
	for _, it := range ScanAll(env).Items {
		if strings.Contains(it.Location, "credential") || strings.Contains(it.Location, "connection") ||
			strings.Contains(it.Location, "supervisor") || strings.Contains(it.Location, "Grok Bot") {
			t.Errorf("a finding from %s", it.Location)
		}
	}
}

func TestGrokBotIsNotReadFromARepository(t *testing.T) {
	repo := t.TempDir()
	writePostureFile(t, filepath.Join(repo, ".grokbot", "settings.json"), `{"localToolPermission":"always"}`)
	for _, it := range ScanRepo(repo).Items {
		if it.Client == grokBotClient {
			t.Errorf("a repository's file was read: %+v", it)
		}
	}
}

func TestGrokBotChecksHaveTitles(t *testing.T) {
	for _, c := range []string{"local_always", "local_ask", "local_unwrapped", "egress_through_host", "messages_send", "security_key_proxy", "computer_use"} {
		if r := RuleFor(c); r.Title == c {
			t.Errorf("%s has no title", c)
		}
	}
}
