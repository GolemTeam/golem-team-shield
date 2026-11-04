package defscan

import "regexp"

var skillScannerEngineRE = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*-skill-scanner$`)

// SkillScannerEngine reports whether an engine id is a Skill Scanner adapter's,
// <adapter>-skill-scanner (db/256). Each adapter in skill-scanner/adapters/ files
// under its own id, so a stored finding says which scanner produced it, and a
// new adapter is an engine without a change here or in the schema.
func SkillScannerEngine(engine string) bool {
	return len(engine) <= 32 && skillScannerEngineRE.MatchString(engine)
}
