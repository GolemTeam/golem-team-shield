package defscan

import "testing"

func TestAnyAdaptersEngineIsASkillScanner(t *testing.T) {
	for _, ok := range []string{"cisco-skill-scanner", "acme-labs-skill-scanner"} {
		if !SkillScannerEngine(ok) {
			t.Errorf("%s is a Skill Scanner engine", ok)
		}
	}
	for _, bad := range []string{"skill-scanner", "-skill-scanner", "Cisco-skill-scanner", "golem-llm", "a_b-skill-scanner", "averyveryverylongvendor-skill-scanner"} {
		if SkillScannerEngine(bad) {
			t.Errorf("%s is not", bad)
		}
	}
}
