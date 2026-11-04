package defscan

import (
	"encoding/json"
	"testing"

	"github.com/GolemTeam/golem-team-shield/internal/definition"
)

func pkgSet(refs []PackageRef) map[string]string {
	m := map[string]string{}
	for _, r := range refs {
		m[r.Ecosystem+":"+r.Name] = r.Version
	}
	return m
}

func TestPackagesAreReadFromManifestsAndCommands(t *testing.T) {
	s := definition.Build("plugin", "p", "config_scan", []definition.Part{
		file("package.json", `{"name":"me","dependencies":{"Left-Pad":"1.3.0","chalk":"^5.0.0"},"devDependencies":{"jest":"29.0.0"}}`),
		file("requirements.txt", "requests==2.31.0\nFlask_Login>=0.6\n# comment\n-r other.txt\n"),
		file("SKILL.md", "Set up with `npx -y @acme/mcp-server@1.0.2 --port 3000`, then\npip install --upgrade colorama==0.4.6 ./local\nand `uvx ruff check .`\n"),
	})
	got := pkgSet(Packages(s))
	want := map[string]string{
		"npm:left-pad": "1.3.0", "npm:chalk": "", "npm:@acme/mcp-server": "1.0.2",
		"PyPI:requests": "2.31.0", "PyPI:flask-login": "", "PyPI:colorama": "0.4.6", "PyPI:ruff": "",
	}
	for k, v := range want {
		if gv, ok := got[k]; !ok || gv != v {
			t.Errorf("%s: got %q (present %v), want %q", k, gv, ok, v)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected package %s", k)
		}
	}
}

func TestAPackageSaysWhereItIsNamed(t *testing.T) {
	body := "Install:\nnpm install evil-pkg@2.0.0\n"
	refs := Packages(definition.Build("skill", "s", "config_scan", []definition.Part{file("SKILL.md", body)}))
	if len(refs) != 1 || refs[0].At.Line != 2 || body[refs[0].At.Start:refs[0].At.End] != "evil-pkg@2.0.0" || refs[0].At.PartName != "SKILL.md" {
		t.Fatalf("refs %+v", refs)
	}
}

func TestNamesNormalizeAsTheRegistriesDo(t *testing.T) {
	if NormalizePackage(EcosystemPyPI, "Flask_Login.Ext") != "flask-login-ext" || NormalizePackage(EcosystemNPM, "@Acme/X") != "@acme/x" {
		t.Error("normalization")
	}
}

// Prose about a command is not the command, and a flag's value is not a package.
func TestProseAndFlagValuesNameNoPackage(t *testing.T) {
	s := definition.Build("plugin", "p", "config_scan", []definition.Part{
		file("SKILL.md", "Note that pip install is also slow, so npx is required.\n\n```\npip install -r requirements.txt --index-url https://x.example/simple\n```\n"),
		file("hooks/setup.py", "# pip install is memory heavy so it can take a while\nsubprocess.run('pip install rich')\n"),
	})
	got := pkgSet(Packages(s))
	if len(got) != 1 || got["PyPI:rich"] != "" {
		t.Fatalf("packages %v", got)
	}
}

// A server's launch names the package it runs, which is checked like any other.
func TestALaunchNamesThePackageItRuns(t *testing.T) {
	l, _ := ParseLaunch("", "npx", []string{"-y", "evil-typo@2.0.0", "--key", "sk-proj-abcdefghijklmnopqrstuvwxyz012345"}, "")
	b, _ := json.Marshal(l)
	part, err := definition.JSON(definition.KindLaunch, "launch", b)
	if err != nil {
		t.Fatal(err)
	}
	refs := Packages(definition.Build("mcp_server", "mcp-evil", definition.SourceLaunch, []definition.Part{part}))
	if len(refs) != 1 || refs[0].Name != "evil-typo" || refs[0].Version != "2.0.0" || refs[0].At.Field != "package" ||
		refs[0].At.Evidence != "npx evil-typo@2.0.0" {
		t.Fatalf("refs %+v", refs)
	}
}
