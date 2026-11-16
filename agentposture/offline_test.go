package agentposture

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The report promises it sent nothing and ran nothing, so the package and
// everything it imports must be unable to: an import is enough for a later
// change to start calling it without anyone noticing.
var offlineForbidden = []string{"net", "net/http", "net/rpc", "net/smtp", "crypto/tls", "os/exec"}

// golang.org/x/sys/windows imports net for the socket types in its Windows
// API bindings; the scan uses the package to read the registry.
var offlineExempt = map[string]bool{"golang.org/x/sys/windows": true}

func TestThePackageImportsNoNetworkOrExecCode(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go command")
	}
	for _, goos := range []string{"darwin", "linux", "windows"} {
		cmd := exec.Command("go", "list", "-deps", "-f", `{{.ImportPath}} {{join .Imports " "}}`, ".")
		cmd.Env = append(os.Environ(), "GOOS="+goos)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s: go list: %v", goos, err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			pkg, imports, _ := strings.Cut(line, " ")
			if first, _, _ := strings.Cut(pkg, "/"); !strings.Contains(first, ".") || offlineExempt[pkg] {
				continue
			}
			for _, imp := range strings.Fields(imports) {
				for _, bad := range offlineForbidden {
					if imp == bad {
						t.Errorf("%s: %s imports %s", goos, pkg, imp)
					}
				}
			}
		}
	}
}
