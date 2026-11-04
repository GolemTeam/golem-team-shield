package attacktech

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestValidRejectsAnUnknownID(t *testing.T) {
	for _, bad := range []string{"AML.T9999", "T9999", "prompt injection", "ATLAS"} {
		if Valid(bad) {
			t.Errorf("%q must not be accepted", bad)
		}
		if err := Validate(bad); err == nil || !strings.Contains(err.Error(), bad) {
			t.Errorf("the error for %q must name it, got %v", bad, err)
		}
	}
}

// The empty string is valid on purpose. Requiring a technique would push a
// classifier toward the nearest-looking label, and a wrong ID in a SIEM is worse
// than no ID: one is a false lead, the other is an absence.
func TestTheEmptyTechniqueIsValid(t *testing.T) {
	if !Valid("") {
		t.Fatal("no technique named must be an allowed answer")
	}
	if err := Validate(""); err != nil {
		t.Fatalf("empty must validate, got %v", err)
	}
}

// Every entry needs a source. An ID nobody can check is how a fabricated technique
// reaches a customer's dashboard looking authoritative, and the catalogue being
// small is the whole reason to be strict about it.
func TestEveryTechniqueCitesASource(t *testing.T) {
	for _, tc := range All() {
		if strings.TrimSpace(tc.Source) == "" {
			t.Errorf("%s cites no source", tc.ID)
		}
		if strings.TrimSpace(tc.Name) == "" {
			t.Errorf("%s has no name", tc.ID)
		}
		if tc.Framework != ATLAS && tc.Framework != ATTACK {
			t.Errorf("%s has framework %q", tc.ID, tc.Framework)
		}
		if tc.Framework == ATLAS && !strings.HasPrefix(tc.ID, "AML.T") {
			t.Errorf("%s is atlas but not an AML.T id", tc.ID)
		}
		if tc.Framework == ATTACK && !regexp.MustCompile(`^T\d{4}`).MatchString(tc.ID) {
			t.Errorf("%s is attack but not a Txxxx id", tc.ID)
		}
	}
}

// This package is the authority and db/105 seeds from it, so the two can drift the
// moment someone adds an entry to one. A Go catalogue holding an ID the database
// rejects fails at INSERT time in production rather than here.
func TestTheMigrationSeedMatchesTheCatalogue(t *testing.T) {
	// EVERY migration, not one named file. db/105 is already applied, and
	// deploy/migrate.sh keys schema_migrations.version on the basename — so editing
	// it does not re-run it and later entries must arrive in later files. A test
	// pinned to a single migration would force the wrong fix: editing an applied
	// one, which silently seeds nothing in any database that has already run it.
	files, err := filepath.Glob("../../db/*.sql")
	if err != nil || len(files) == 0 {
		t.Skipf("migrations not readable from here: %v", err)
	}
	var sql strings.Builder
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		sql.Write(raw)
	}
	all := sql.String()

	for _, tc := range All() {
		if !strings.Contains(all, "'"+tc.ID+"'") {
			t.Errorf("%s is in the catalogue but no migration seeds it", tc.ID)
			continue
		}
		if !strings.Contains(all, "'"+tc.Name+"'") {
			t.Errorf("%s: name %q not found in any migration", tc.ID, tc.Name)
		}
	}

	// A SET, not a count. Re-seeding an existing id is the documented upsert shape
	// (ON CONFLICT DO UPDATE), so counting occurrences would fail the moment a
	// migration corrects an earlier row.
	seeded := map[string]bool{}
	for _, m := range regexp.MustCompile(`\('((?:AML\.)?T[0-9.]+)',`).FindAllStringSubmatch(all, -1) {
		seeded[m[1]] = true
	}
	if len(seeded) == 0 {
		t.Fatal("no seeded ids parsed out of db/*.sql; the regex or the files changed shape")
	}
	for id := range seeded {
		if !Valid(id) {
			t.Errorf("a migration seeds %s, which the catalogue does not know", id)
		}
	}
	if len(seeded) != len(All()) {
		t.Errorf("migrations seed %d distinct ids, catalogue holds %d", len(seeded), len(All()))
	}
}

func TestLookupReturnsTheEntry(t *testing.T) {
	got, ok := Lookup("AML.T0051.001")
	if !ok {
		t.Fatal("indirect prompt injection must be in the catalogue")
	}
	if got.Framework != ATLAS || got.Tactic != "Initial Access" {
		t.Fatalf("unexpected entry: %+v", got)
	}
	if _, ok := Lookup("nope"); ok {
		t.Fatal("an unknown id must not resolve")
	}
}
