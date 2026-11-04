package defscan

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The rules are published on their own (golem-check), so they import no
// catalog: pkg/assetref carries Golem's own principals.
func TestTheRulesImportNoCatalog(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range parsed.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if strings.HasPrefix(path, "github.com/golem/") && path != "github.com/GolemTeam/golem-team-shield/internal/definition" && path != "github.com/GolemTeam/golem-team-shield/internal/cmdpattern" {
				t.Errorf("%s imports %s", f, path)
			}
		}
	}
}
