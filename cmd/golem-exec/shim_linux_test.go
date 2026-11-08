package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/GolemTeam/golem-team-shield/shield"
)

// The jail stage re-executes /proc/self/exe, which under test is this binary.
func TestMain(m *testing.M) {
	switch filepath.Base(os.Args[0]) {
	case jailStage:
		os.Exit(runJailStage(os.Args[1:], false))
	case jailStagePrepared:
		os.Exit(runJailStage(os.Args[1:], true))
	case jailSetup:
		os.Exit(runJailSetup(os.Args[1:]))
	case jailLauncher:
		os.Exit(runJailLauncher(os.Args[1:]))
	}
	if addr := os.Getenv("GOLEM_EXEC_DIAL"); addr != "" {
		network, address, _ := strings.Cut(addr, ":")
		c, err := net.Dial(network, address)
		if err != nil {
			os.Exit(7)
		}
		c.Close()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

const testKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nPRIVATE\n-----END OPENSSH PRIVATE KEY-----\n"

func needLandlock(t *testing.T) {
	t.Helper()
	if landlockABI() < shield.LandlockMinABI {
		t.Skip("this kernel has no Landlock")
	}
}

func plant(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func linuxShim(t *testing.T, p shield.Policy) (*shim, *fakeWitness, *bytes.Buffer) {
	t.Helper()
	needLandlock(t)
	w := newFakeWitness(t, p)
	s, stdout, _ := testShim(t, w.URL)
	s.cwd = filepath.Join(s.cwd, "repo")
	if err := os.MkdirAll(filepath.Join(s.cwd, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(s.cwd); err != nil {
		t.Fatal(err)
	}
	return s, w, stdout
}

func TestLinuxShimJailsTheCommandAndReportsTheRun(t *testing.T) {
	s, w, out := linuxShim(t, shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.AllGrants()})
	plant(t, filepath.Join(s.home, ".ssh", "id_ed25519"), testKey)
	plant(t, filepath.Join(s.home, ".ssh", "config"), "Host x\n")

	script := `/bin/sh -c "cat $HOME/.ssh/id_ed25519" && echo LEAKED; cat $HOME/.ssh/config; echo "token=[$GITHUB_TOKEN]"; exit 3`
	if code := s.run("/bin/bash", []string{"-c", script}); code != 3 {
		t.Fatalf("exit %d, want the command's own 3", code)
	}
	got := out.String()
	if strings.Contains(got, "PRIVATE") || strings.Contains(got, "LEAKED") {
		t.Errorf("key read through an absolute /bin/sh: %s", got)
	}
	if !strings.Contains(got, "Host x") {
		t.Errorf("ssh config wasn't readable: %s", got)
	}
	if !strings.Contains(got, "token=[]") {
		t.Errorf("GITHUB_TOKEN reached the command: %s", got)
	}
	if len(w.runs) != 1 {
		t.Fatalf("runs %d", len(w.runs))
	}
	rec := w.runs[0]
	if rec.Jail != shield.JailLandlock || rec.ExitCode != 3 || len(rec.PolicyHash) != 64 || rec.RunTag != w.requests[0].RunTag {
		t.Errorf("run record %+v", rec)
	}
}

func TestLinuxCleanSessionWritesButNotStartupFiles(t *testing.T) {
	s, _, out := linuxShim(t, shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.AllGrants()})
	plant(t, filepath.Join(s.home, ".bashrc"), "# rc\n")
	plant(t, filepath.Join(s.home, ".cache", "keep"), "")
	script := `echo x >> $HOME/.bashrc && echo RC; echo x > $HOME/.bash_profile && echo PROFILE;` +
		` echo x > $HOME/.cache/new && echo CACHE; echo x > new.go && echo WS; echo done`
	s.run("/bin/bash", []string{"-c", script})
	got := out.String()
	if strings.Contains(got, "RC") || strings.Contains(got, "PROFILE") {
		t.Errorf("a startup file was written: %s", got)
	}
	if !strings.Contains(got, "CACHE") || !strings.Contains(got, "WS") {
		t.Errorf("ordinary writes failed: %s", got)
	}
}

func TestLinuxTaintedSessionCantConnectOrWriteOutsideTheWorkspace(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	s, w, out := linuxShim(t, shield.Policy{Enforce: true, State: shield.Tainted, Grants: shield.AllGrants()})
	script := `(exec 3<>/dev/tcp/127.0.0.1/` + port + `) 2>/dev/null && echo CONNECTED;` +
		` touch $HOME/x 2>/dev/null && echo HOMEWRITE; echo x > ws.txt && echo WS; echo x > $TMPDIR/t && echo TMP; true`
	s.run("/bin/bash", []string{"-c", script})
	got := out.String()
	if strings.Contains(got, "CONNECTED") || strings.Contains(got, "HOMEWRITE") {
		t.Errorf("tainted command escaped: %s", got)
	}
	if !strings.Contains(got, "WS") || !strings.Contains(got, "TMP") {
		t.Errorf("tainted command lost its workspace or temp dir: %s", got)
	}
	if len(w.runs) != 1 || w.runs[0].State != shield.Tainted {
		t.Fatalf("runs %+v", w.runs)
	}
}

func TestLinuxTaintedSessionStillWritesTheHarnessCwdFile(t *testing.T) {
	s, _, out := linuxShim(t, shield.Policy{Enforce: true, State: shield.Tainted})
	harness := t.TempDir()
	s.env = append(s.env, "CLAUDECODE=1", "CLAUDE_CODE_TMPDIR="+harness)
	cwdFile := filepath.Join(harness, "claude-ab12-cwd")
	s.run("/bin/bash", []string{"-c", "pwd -P >| " + cwdFile + " && echo OK; echo x > " + filepath.Join(harness, "other") + " && echo OTHER; true"})
	if got := out.String(); !strings.Contains(got, "OK") || strings.Contains(got, "OTHER") {
		t.Errorf("harness file: %s", got)
	}
	if b, _ := os.ReadFile(cwdFile); strings.TrimSpace(string(b)) != realPath(s.cwd) {
		t.Errorf("cwd file holds %q", b)
	}
}

func TestLinuxGrantsOffCloseUnixSockets(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	self, _ := os.Executable()

	s, _, _ := linuxShim(t, shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.AllGrants()})
	s.env = append(s.env, "GOLEM_EXEC_DIAL=unix:"+sock)
	if code := s.run(self, nil); code != 0 {
		t.Fatalf("with every grant the socket was refused: exit %d", code)
	}
	s, _, _ = linuxShim(t, shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.Grants{Agent: true, Cloud: true}})
	s.env = append(s.env, "GOLEM_EXEC_DIAL=unix:"+sock)
	if code := s.run(self, nil); code != 7 {
		t.Fatalf("Docker grant off, exit %d, want the dial to fail", code)
	}
}

func TestLinuxBackgroundChildStaysJailed(t *testing.T) {
	s, _, out := linuxShim(t, shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.AllGrants()})
	plant(t, filepath.Join(s.home, ".ssh", "id_ed25519"), testKey)
	marker := filepath.Join(s.cwd, "bg.out")
	s.run("/bin/bash", []string{"-c", `nohup sh -c "cat $HOME/.ssh/id_ed25519 > ` + marker + ` 2>&1" >/dev/null 2>&1 & wait`})
	b, _ := os.ReadFile(marker)
	if strings.Contains(string(b), "PRIVATE") {
		t.Fatalf("a background child read the key: %s %s", b, out.String())
	}
}

func TestLinuxWithoutAWitnessStillJails(t *testing.T) {
	needLandlock(t)
	s, out, _ := testShim(t, "http://127.0.0.1:1")
	plant(t, filepath.Join(s.home, ".ssh", "id_ed25519"), testKey)
	s.run("/bin/bash", []string{"-c", "cat $HOME/.ssh/id_ed25519"})
	if strings.Contains(out.String(), "PRIVATE") {
		t.Fatal("the baseline jail didn't hold without a witness")
	}
}

func TestLinuxJailStageRefusesWithoutASpec(t *testing.T) {
	needLandlock(t)
	self, _ := os.Executable()
	cmd := exec.Command(self)
	cmd.Args = []string{jailStage, "/bin/sh", "-c", "echo RAN"}
	b, err := cmd.CombinedOutput()
	if strings.Contains(string(b), "RAN") {
		t.Fatalf("the stage ran a command without its rules: %s", b)
	}
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 126 {
		t.Fatalf("exit %v, want 126", err)
	}
}

func TestLinuxShimKeepsBrowserChatAndPasswordStoresFromTheCommand(t *testing.T) {
	s, _, out := linuxShim(t, shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.AllGrants()})
	for _, f := range []string{
		".mozilla/firefox/x.default/cookies.sqlite",
		".config/google-chrome/Default/Cookies",
		".config/Slack/storage/x",
		".password-store/github.gpg",
		".thunderbird/x/prefs.js",
	} {
		plant(t, filepath.Join(s.home, f), "SECRET\n")
	}
	plant(t, filepath.Join(s.home, ".config", "nvim", "init.lua"), "OPEN\n")
	script := `cd $HOME; cat .mozilla/firefox/x.default/cookies.sqlite .config/google-chrome/Default/Cookies` +
		` .config/Slack/storage/x .password-store/github.gpg .thunderbird/x/prefs.js .config/nvim/init.lua;` +
		` echo x > .mozilla/firefox/x.default/user.js && echo PLANTED; echo done`
	s.run("/bin/bash", []string{"-c", script})
	got := out.String()
	if strings.Contains(got, "SECRET") || strings.Contains(got, "PLANTED") {
		t.Errorf("an app's store was reachable: %s", got)
	}
	if !strings.Contains(got, "OPEN") || !strings.Contains(got, "done") {
		t.Errorf("the rest of ~/.config wasn't readable: %s", got)
	}
}

func allowlistScript(other string) string {
	return `(exec 3<>/dev/tcp/127.0.0.1/` + other + `) 2>/dev/null && echo DIRECT;` +
		` (exec 3<>/dev/tcp/1.1.1.1/443) 2>/dev/null && echo PUBLIC;` +
		` (exec 3<>/dev/udp/1.1.1.1/53) 2>/dev/null && echo UDP;` +
		` p=${HTTPS_PROXY##*:}; exec 3<>/dev/tcp/127.0.0.1/$p && printf 'CONNECT evil.test:443 HTTP/1.1\r\nHost: evil.test\r\n\r\n' >&3 && head -1 <&3; true`
}

func TestLinuxAllowlistedNetworkReachesOnlyTheProxy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	other := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	p := shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.AllGrants(), Network: shield.NetworkAllowlist, AllowedHosts: []string{"github.com"}}
	for _, fallback := range []bool{false, true} {
		s, w, out := linuxShim(t, p)
		s.noNamespace = fallback
		stderr := s.stderr.(*bytes.Buffer)
		s.run("/bin/bash", []string{"-c", allowlistScript(other)})
		got := out.String()
		for _, leak := range []string{"DIRECT", "PUBLIC", "UDP"} {
			if strings.Contains(got, leak) {
				t.Errorf("fallback=%v: %s got out: %s", fallback, leak, got)
			}
		}
		if !strings.Contains(got, "403") {
			t.Errorf("fallback=%v: the proxy didn't answer: %s / %s", fallback, got, stderr)
		}
		if !strings.Contains(stderr.String(), "the shield refused evil.test:443: not in the allowed hosts. Allow it in the console") {
			t.Errorf("fallback=%v: the refusal wasn't named: %s", fallback, stderr)
		}
		if len(w.runs) != 1 {
			t.Fatalf("runs %d", len(w.runs))
		}
		rec := w.runs[0]
		want := shield.NetLandlockPort
		if !fallback && rec.Net == shield.NetNamespace {
			want = shield.NetNamespace
		}
		t.Logf("fallback=%v: net %s", fallback, rec.Net)
		if !fallback && os.Getenv("GOLEM_EXEC_EXPECT_NAMESPACE") == "1" && rec.Net != shield.NetNamespace {
			t.Errorf("expected a namespace here, got %s", rec.Net)
		}
		if rec.Net != want || len(rec.Egress) != 1 || rec.Egress[0].Host != "evil.test" || rec.Egress[0].Allowed {
			t.Errorf("fallback=%v: run record net %q egress %+v", fallback, rec.Net, rec.Egress)
		}
	}
}

func TestLinuxWorkspaceWritesStayInTheRoots(t *testing.T) {
	s, w, out := linuxShim(t, shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.AllGrants(), Writes: shield.WritesWorkspace})
	plant(t, filepath.Join(s.home, ".cache", "keep"), "")
	plant(t, filepath.Join(s.home, "notes"), "")
	script := `echo x > ws.txt && echo WS; echo x > $TMPDIR/t && echo TMP; echo x > $HOME/.cache/new && echo CACHE;` +
		` echo x >> $HOME/notes && echo HOME; mkdir $HOME/newdir 2>/dev/null && echo MKDIR; true`
	s.run("/bin/bash", []string{"-c", script})
	got := out.String()
	for _, want := range []string{"WS", "TMP", "CACHE"} {
		if !strings.Contains(got, want) {
			t.Errorf("%s wasn't writable: %s", want, got)
		}
	}
	if strings.Contains(got, "HOME") || strings.Contains(got, "MKDIR") {
		t.Errorf("a write left the roots: %s", got)
	}
	if len(w.runs) != 1 || w.runs[0].Writes != "workspace" {
		t.Errorf("runs %+v", w.runs)
	}
}

func TestLinuxNamespacedCommandHasNoCapabilities(t *testing.T) {
	p := shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.AllGrants(), Network: shield.NetworkAllowlist}
	s, w, out := linuxShim(t, p)
	s.run("/bin/bash", []string{"-c", `grep -E '^Cap(Eff|Prm|Amb)' /proc/self/status; id -u`})
	if len(w.runs) != 1 || w.runs[0].Net != shield.NetNamespace {
		if os.Getenv("GOLEM_EXEC_EXPECT_NAMESPACE") == "1" {
			t.Fatalf("expected a namespace here, got runs %+v", w.runs)
		}
		t.Skipf("no namespace here (net %q)", w.runs[0].Net)
	}
	got := out.String()
	if strings.Count(got, "0000000000000000") != 3 || !strings.Contains(got, strconv.Itoa(os.Getuid())) {
		t.Errorf("the command kept capabilities or changed user: %s", got)
	}
}

func TestLinuxConfinedWritesOutsideARepositoryAndIntoNewCaches(t *testing.T) {
	needLandlock(t)
	w := newFakeWitness(t, shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.AllGrants(), Writes: shield.WritesWorkspace})
	s, out, _ := testShim(t, w.URL)
	s.cwd = filepath.Join(s.cwd, "plain")
	if err := os.MkdirAll(s.cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(s.home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(s.cwd); err != nil {
		t.Fatal(err)
	}
	script := `echo x > inside.txt && echo INSIDE; echo x > $HOME/.cache/ok && echo CACHE; mkdir -p $HOME/.npm/_cacache && echo NPM;` +
		` echo x > $HOME/outside 2>/dev/null && echo OUTSIDE; true`
	s.run("/bin/bash", []string{"-c", script})
	got := out.String()
	for _, want := range []string{"INSIDE", "CACHE", "NPM"} {
		if !strings.Contains(got, want) {
			t.Errorf("%s wasn't writable: %s", want, got)
		}
	}
	if strings.Contains(got, "OUTSIDE") {
		t.Errorf("a write left the roots: %s", got)
	}
	if _, err := os.Stat(filepath.Join(s.home, "go")); err == nil {
		t.Error("a cache for a tool the machine doesn't have was created")
	}
}

// Run as root with GOLEM_EXEC_APPARMOR=install or remove, the test binary
// installs itself as the profiled copy or takes it out again, so the tests
// that follow, run as the user, start their stage from it.
func TestLinuxAppArmorProfile(t *testing.T) {
	action := os.Getenv("GOLEM_EXEC_APPARMOR")
	if action == "" {
		t.Skip("set GOLEM_EXEC_APPARMOR=install or remove, as root")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := changeAppArmor(action == "install", self); err != nil {
		t.Fatal(err)
	}
	installed, current := shield.AppArmorCopy()
	if action == "remove" {
		if installed {
			t.Fatal("still installed after remove")
		}
		for _, p := range []string{appArmorProfile, appArmorStage} {
			if _, err := os.Stat(p); err == nil {
				t.Errorf("%s is still there", p)
			}
		}
		return
	}
	if !installed || !current || !shield.UserNSRestricted() {
		t.Fatalf("after install: installed %v, current %v, restricted %v", installed, current, shield.UserNSRestricted())
	}
	if b, err := os.ReadFile("/sys/kernel/security/apparmor/profiles"); err != nil || !strings.Contains(string(b), "golem-exec (") {
		t.Errorf("the profile isn't loaded: %v", err)
	}
}

// The profile lets the copy make namespaces, and nothing else: the command
// it starts can make one but hold no capability in it, no process can trace
// the launcher, and the command can read its own children but no other
// process of the user's.
func TestLinuxProfiledLauncherHandsTheCommandNothing(t *testing.T) {
	if profiledLauncher() == "" {
		if os.Getenv("GOLEM_EXEC_EXPECT_NAMESPACE") == "1" && shield.UserNSRestricted() {
			t.Fatal("no profiled copy to launch from")
		}
		t.Skip("no profiled copy of golem-exec here")
	}
	if os.Geteuid() != 0 && shield.LinuxNamespaces() != shield.NamespacesProfiled {
		t.Errorf("golem doctor would say %s", shield.LinuxNamespaces())
	}
	p := shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.AllGrants(), Network: shield.NetworkAllowlist}
	s, w, out := linuxShim(t, p)
	marker := filepath.Join(s.cwd, "launcher-pid")
	script := `unshare -Urn sh -c 'ip link set lo up && echo NESTEDCAP' 2>/dev/null;` +
		` sleep 5 & cat /proc/$!/environ >/dev/null && echo CHILDREAD;` +
		` cat /proc/` + strconv.Itoa(os.Getpid()) + `/environ >/dev/null 2>&1 && echo OUTSIDEREAD;` +
		` echo $PPID $$ > ` + marker + `.tmp && mv ` + marker + `.tmp ` + marker + `; sleep 3; echo done`
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.run("/bin/bash", []string{"-c", script})
	}()
	var pid int
	for i := 0; i < 50 && pid == 0; i++ {
		if b, err := os.ReadFile(marker); err == nil {
			f := strings.Fields(string(b))
			if len(f) == 2 {
				pid, _ = strconv.Atoi(f[0])
			}
		} else {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if pid == 0 {
		<-done
		t.Fatalf("the command never ran: %s", out.String())
	}
	cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if !strings.HasPrefix(string(cmdline), jailLauncher+"\x00") {
		t.Errorf("the command's parent is %q, not the launcher", cmdline)
	}
	traced := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		err := unix.PtraceAttach(pid)
		if err == nil {
			_, _ = unix.Wait4(pid, nil, 0, nil)
			_ = unix.PtraceDetach(pid)
		}
		traced <- err
	}()
	if err := <-traced; err == nil {
		t.Error("the launcher could be traced")
	}
	if _, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid)); err == nil {
		t.Error("the launcher's environment could be read")
	}
	<-done
	got := out.String()
	if strings.Contains(got, "NESTEDCAP") || !strings.Contains(got, "done") {
		t.Errorf("the command made a namespace with capabilities, or didn't finish: %s", got)
	}
	if !strings.Contains(got, "CHILDREAD") || strings.Contains(got, "OUTSIDEREAD") {
		t.Errorf("the command couldn't read its own child, or could read the shim: %s", got)
	}
	if len(w.runs) != 1 || w.runs[0].Net != shield.NetNamespace {
		t.Errorf("runs %+v", w.runs)
	}
}

func TestLinuxProjectMountPlanKeepsWorkingFoldersWritable(t *testing.T) {
	root := t.TempDir()
	for _, f := range []string{".claude/settings.json", ".cursor/rules/r.md", ".github/workflows/ci.yml", ".github/hooks/a.json", "src/main.go"} {
		plant(t, filepath.Join(root, f), "x")
	}
	c := shield.Context{Workspace: []string{root}, WorkingDir: filepath.Join(root, "src")}
	plan, unheld := planProjectMounts(projectPaths(c), c.Workspace, workingFolders(c))
	ro, rw := map[string]bool{}, map[string]bool{}
	for _, b := range plan.Binds {
		if b.ReadOnly {
			ro[strings.TrimPrefix(b.Path, root+"/")] = true
		} else {
			rw[strings.TrimPrefix(b.Path, root+"/")] = true
		}
	}
	for _, want := range []string{".claude/settings.json", ".github/hooks", ".cursor", ".github", ".claude"} {
		if !ro[want] {
			t.Errorf("%s isn't bound read-only: ro %v", want, ro)
		}
	}
	for _, want := range []string{".cursor/rules", ".github/workflows", "src"} {
		if !rw[want] {
			t.Errorf("%s isn't bound writable: rw %v", want, rw)
		}
	}
	for _, never := range []string{"", "src"} {
		if ro[never] {
			t.Errorf("%q, where people work, is bound read-only", never)
		}
	}
	missing := map[string]bool{}
	for _, p := range unheld {
		missing[strings.TrimPrefix(p.Path, root+"/")] = true
	}
	for _, want := range []string{".mcp.json", ".gemini/settings.json", "src/.mcp.json", "src/.codex/config.toml"} {
		if !missing[want] {
			t.Errorf("%s is neither held nor left for the check: %v", want, missing)
		}
	}
}

func TestLinuxProjectFilesAreHeld(t *testing.T) {
	s, w, out := linuxShim(t, shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.AllGrants()})
	for f, body := range map[string]string{
		".claude/settings.json": "ORIG", ".claude/notes.md": "n", ".cursor/rules/r.md": "r",
		".github/hooks/a.json": "ORIG", ".github/workflows/ci.yml": "ci",
	} {
		plant(t, filepath.Join(s.cwd, f), body)
	}
	script := `echo X > .claude/settings.json && echo W1; mv .claude c2 && echo W2; rm -f .claude/settings.json && echo W3;` +
		` mkdir y && echo X > y/settings.json; mv -T y .claude 2>/dev/null && echo W4;` +
		` echo X > .cursor/hooks.json && echo W5; echo ok > .cursor/rules/r2.md && echo OK1;` +
		` echo X > .github/hooks/a.json && echo W6; echo X > .github/hooks/b.json && echo W7;` +
		` mkdir .github/copilot && echo W8; echo ok >> .github/workflows/ci.yml && echo OK2;` +
		` echo ok > .claude/notes.md && echo OK3; touch newfile && echo OK4; true`
	s.run("/bin/bash", []string{"-c", script})
	if len(w.runs) != 1 || w.runs[0].Files != shield.FilesHeld {
		if os.Getenv("GOLEM_EXEC_EXPECT_NAMESPACE") == "1" {
			t.Fatalf("expected the files held, runs %+v", w.runs)
		}
		t.Skipf("no namespace here (runs %+v)", w.runs)
	}
	got := out.String()
	for _, bad := range []string{"W1", "W2", "W3", "W4", "W5", "W6", "W7", "W8"} {
		if strings.Contains(got, bad) {
			t.Errorf("%s got through: %s", bad, got)
		}
	}
	for _, ok := range []string{"OK1", "OK2", "OK3", "OK4"} {
		if !strings.Contains(got, ok) {
			t.Errorf("%s, ordinary work, was refused: %s", ok, got)
		}
	}
	for f, want := range map[string]string{".claude/settings.json": "ORIG", ".github/hooks/a.json": "ORIG"} {
		if b, _ := os.ReadFile(filepath.Join(s.cwd, f)); string(b) != want {
			t.Errorf("%s now holds %q", f, b)
		}
	}
	for _, f := range []string{".cursor/hooks.json", ".github/hooks/b.json", ".github/copilot"} {
		if _, err := os.Stat(filepath.Join(s.cwd, f)); err == nil {
			t.Errorf("%s was created", f)
		}
	}
}

// A work tree without the agents' folders gets them, held, so a command
// can't make their settings there, at the root or on the way down.
func TestLinuxMissingProjectFoldersAreMadeAndHeld(t *testing.T) {
	s, w, out := linuxShim(t, shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.AllGrants()})
	sub := filepath.Join(s.cwd, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	s.cwd = sub
	if err := os.Chdir(sub); err != nil {
		t.Fatal(err)
	}
	script := `mkdir -p .claude ../.cursor; echo X > ../.claude/settings.json && echo W1; rmdir ../.claude && echo W2;` +
		` echo X > ../.cursor/hooks.json && echo W3; echo X > .gemini/settings.json && echo W4;` +
		` touch ../newfile newfile2 && echo OK1; true`
	s.run("/bin/bash", []string{"-c", script})
	if len(w.runs) != 1 || w.runs[0].Files != shield.FilesHeld {
		if os.Getenv("GOLEM_EXEC_EXPECT_NAMESPACE") == "1" {
			t.Fatalf("expected the files held, runs %+v", w.runs)
		}
		t.Skipf("no namespace here (runs %+v)", w.runs)
	}
	got := out.String()
	for _, bad := range []string{"W1", "W2", "W3", "W4"} {
		if strings.Contains(got, bad) {
			t.Errorf("%s got through: %s", bad, got)
		}
	}
	if !strings.Contains(got, "OK1") {
		t.Errorf("ordinary work was refused: %s", got)
	}
	for _, d := range []string{"../.claude", "../.cursor", "../.vscode", ".gemini", ".claude"} {
		entries, err := os.ReadDir(filepath.Join(sub, d))
		if err != nil || len(entries) != 0 {
			t.Errorf("%s: %v %v", d, entries, err)
		}
	}
}

// A folder on the way down to the working directory is bound onto itself,
// so a relative path from inside it must still meet the read-only binds.
func TestLinuxProjectFilesAreHeldBelowTheWorkingDirectory(t *testing.T) {
	s, w, out := linuxShim(t, shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.AllGrants()})
	sub := filepath.Join(s.cwd, "sub")
	plant(t, filepath.Join(sub, ".claude", "settings.json"), "ORIG")
	plant(t, filepath.Join(sub, ".github", "hooks", "a.json"), "ORIG")
	s.cwd = sub
	if err := os.Chdir(sub); err != nil {
		t.Fatal(err)
	}
	s.run("/bin/bash", []string{"-c", `echo X > .claude/settings.json && echo W1; echo X > .github/hooks/a.json && echo W2;` +
		` echo X > .github/hooks/b.json && echo W3; touch newfile && echo OK1; true`})
	if len(w.runs) != 1 || w.runs[0].Files != shield.FilesHeld {
		if os.Getenv("GOLEM_EXEC_EXPECT_NAMESPACE") == "1" {
			t.Fatalf("expected the files held, runs %+v", w.runs)
		}
		t.Skipf("no namespace here (runs %+v)", w.runs)
	}
	got := out.String()
	for _, bad := range []string{"W1", "W2", "W3"} {
		if strings.Contains(got, bad) {
			t.Errorf("%s got through: %s", bad, got)
		}
	}
	if !strings.Contains(got, "OK1") {
		t.Errorf("ordinary work was refused: %s", got)
	}
	for _, f := range []string{".claude/settings.json", ".github/hooks/a.json"} {
		if b, _ := os.ReadFile(filepath.Join(sub, f)); string(b) != "ORIG" {
			t.Errorf("%s now holds %q", f, b)
		}
	}
}
