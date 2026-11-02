package shield

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func TestSSHReadableKeepsWhatIsNotAKey(t *testing.T) {
	// A short base keeps the Unix socket's path under its length limit.
	base := "/tmp"
	if runtime.GOOS == "windows" {
		base = os.TempDir()
	}
	home, err := os.MkdirTemp(base, "gssh")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(home)
	ssh := filepath.Join(home, ".ssh")
	for name, body := range map[string]string{
		"config":                "Include config.d/*\n",
		"config.d/work":         "Host work\n",
		"known_hosts.d/gh":      "github.com ssh-ed25519 AAAA\n",
		"id_ed25519":            "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n",
		"google_compute_engine": "-----BEGIN RSA PRIVATE KEY-----\nx\n",
		"junk_then_key":         "notes\n-----BEGIN EC PRIVATE KEY-----\nx\n",
		"w.ppk":                 "PuTTY-User-Key-File-3: ssh-rsa\n",
		"identity":              "SSH PRIVATE KEY FILE FORMAT 1.1\n",
		"age.txt":               "# created: 2026\nAGE-SECRET-KEY-1QQQ\n",
		"blob":                  "a\x00b",
		"a/b/c/d/e/too_deep":    "Host deep\n",
	} {
		write(t, filepath.Join(ssh, name), body)
	}
	if err := os.WriteFile(filepath.Join(ssh, "huge"), []byte(strings.Repeat("a", sshScanMaxBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	// Windows lets only a privileged or developer-mode user make a symlink.
	if err := os.Symlink(filepath.Join(ssh, "id_ed25519"), filepath.Join(ssh, "alias")); err != nil && runtime.GOOS != "windows" {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", filepath.Join(ssh, "cm.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var got []string
	for _, p := range SSHReadable(home) {
		rel, _ := filepath.Rel(ssh, p)
		got = append(got, filepath.ToSlash(rel))
	}
	sort.Strings(got)
	want := []string{"a", "a/b", "a/b/c", "a/b/c/d", "cm.sock", "config", "config.d", "config.d/work", "known_hosts.d", "known_hosts.d/gh"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("readable =\n %v\nwant\n %v", got, want)
	}
}

func TestSSHReadableWithoutAnSSHDirectory(t *testing.T) {
	if got := SSHReadable(t.TempDir()); got != nil {
		t.Errorf("got %v", got)
	}
}
