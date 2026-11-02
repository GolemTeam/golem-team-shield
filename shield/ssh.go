package shield

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	sshScanMaxEntries = 256
	sshScanMaxDepth   = 4
	// No ssh config or known_hosts is this big. A larger file stays denied, so
	// the scan never stops reading before a key could appear in it.
	sshScanMaxBytes = 1 << 20
)

var privateKeyMarks = [][]byte{
	[]byte("PRIVATE KEY"),
	[]byte("PuTTY-User-Key-File"),
	[]byte("SSH PRIVATE KEY FILE FORMAT"),
	[]byte("AGE-SECRET-KEY-"),
}

// SSHReadable lists what under home/.ssh a jailed command may read: every
// directory, socket and file that isn't a private key, judged by what the file
// holds rather than its name. ~/.ssh is denied whole first, so a key called
// anything stays out of reach while ssh's own files (config.d includes,
// known_hosts.d, a 1Password config) come back. The jail can't write ~/.ssh,
// so a command can't plant a file to pass this.
//
// Anything unreadable, binary, too large or past the scan's bounds stays
// denied. Symlinks are skipped: the kernel checks the path they resolve to.
func SSHReadable(home string) []string {
	root := filepath.Join(home, ".ssh")
	if fi, err := os.Lstat(root); err != nil || !fi.IsDir() {
		return nil
	}
	var out []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || len(out) >= sshScanMaxEntries {
			return fs.SkipDir
		}
		if p == root {
			return nil
		}
		if strings.ContainsAny(p, "\x00\n\r") {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		switch t := d.Type(); {
		case t.IsDir():
			if strings.Count(rel, string(filepath.Separator)) >= sshScanMaxDepth {
				return fs.SkipDir
			}
			out = append(out, p)
		case t&fs.ModeSocket != 0:
			out = append(out, p)
		case t.IsRegular() && !holdsSecret(p):
			out = append(out, p)
		}
		return nil
	})
	return out
}

func holdsSecret(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return true
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, sshScanMaxBytes+1))
	if err != nil || len(b) > sshScanMaxBytes || bytes.IndexByte(b, 0) >= 0 {
		return true
	}
	for _, m := range privateKeyMarks {
		if bytes.Contains(b, m) {
			return true
		}
	}
	return false
}
