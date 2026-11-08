package shield

import (
	"os"
	"testing"
)

func TestLinuxNamespacesProbe(t *testing.T) {
	ns := LinuxNamespaces()
	t.Logf("namespaces here: %s", ns)
	if os.Getenv("GOLEM_EXEC_EXPECT_NAMESPACE") == "1" && !ns.Held() {
		t.Fatalf("expected a namespace, got %s", ns)
	}
	if !UserNSRestricted() && ns != NamespacesOpen && ns != NamespacesNone {
		t.Fatalf("an unrestricted kernel reported %s", ns)
	}
}
