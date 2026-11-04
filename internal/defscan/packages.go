package defscan

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/GolemTeam/golem-team-shield/internal/definition"
)

// The packages a definition names (layer 3, Supply chain): from a bundled
// package.json or requirements file, and from the install and run commands its
// text tells the agent to use. Each is checked against the OSV corpus server-side
// (engine golem-osv); only the names and versions leave the snapshot.

const (
	EcosystemNPM  = "npm"
	EcosystemPyPI = "PyPI"

	OSVVersion   = "osv-2026.10.1"
	maxPackages  = 200
	layerPackage = "package"
)

var osvRules = []Rule{
	{ID: "osv-malicious-package", Title: "Names a package reported as malicious", Layer: layerPackage, Category: "malicious_package",
		Severity: SeverityHigh, Confidence: ConfidenceHigh, Attack: []string{"T1195.002"}, Source: "osv"},
	{ID: "osv-vulnerable-package", Title: "Pins a package version with a serious vulnerability", Layer: layerPackage, Category: "vulnerable_package",
		Severity: SeverityMedium, Confidence: ConfidenceMedium, Attack: []string{"T1195.001"}, Source: "osv"},
}

// OSVRules is the package engine's vocabulary, for titles.
func OSVRules() []Rule { return append([]Rule(nil), osvRules...) }

func OSVRule(id string) (Rule, bool) {
	for _, r := range osvRules {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}

// PackageRef is one package a definition names, where it names it. Version is
// set only when the reference pins one exact version; a range or nothing is
// unpinned, and is judged only against reports covering every version.
type PackageRef struct {
	Ecosystem, Name, Version string
	At                       Finding
}

var pep503 = regexp.MustCompile(`[-_.]+`)

// NormalizePackage is a package's name as the corpus keys it: npm names are
// case-insensitive in practice and PyPI's normalize as PEP 503 says.
func NormalizePackage(ecosystem, name string) string {
	name = strings.TrimSpace(name)
	switch ecosystem {
	case EcosystemPyPI:
		return pep503.ReplaceAllString(strings.ToLower(name), "-")
	case EcosystemNPM:
		return strings.ToLower(name)
	}
	return name
}

var (
	npmNameRE  = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]{0,213}$`)
	pypiNameRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]{0,200}[A-Za-z0-9])?$`)
	exactRE    = regexp.MustCompile(`^v?[0-9]+(\.[0-9A-Za-z-]+)*(\+[0-9A-Za-z.-]+)?$`)

	// A command that installs or runs a package, and what follows it.
	installRE = regexp.MustCompile(`(?m)\b(npx|bunx|pnpm\s+dlx|npm\s+(?:install|i|add)|pnpm\s+(?:add|install)|yarn\s+(?:global\s+)?add|pip3?\s+install|python3?\s+-m\s+pip\s+install|uv\s+pip\s+install|uv\s+add|uvx|pipx\s+(?:install|run))\s+([^\n;&|` + "`" + `]*)`)
	reqLineRE = regexp.MustCompile(`(?m)^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(==\s*[^\s;#,]+|[<>=!~][^#;\n]*)?`)
)

// Packages is every package the snapshot names, at most maxPackages, one per
// ecosystem, name and version.
func Packages(s definition.Snapshot) []PackageRef {
	var out []PackageRef
	seen := map[string]bool{}
	add := func(r PackageRef) {
		r.Name = NormalizePackage(r.Ecosystem, r.Name)
		k := r.Ecosystem + "\x1f" + r.Name + "\x1f" + r.Version
		if r.Name == "" || seen[k] || len(out) >= maxPackages {
			return
		}
		seen[k] = true
		out = append(out, r)
	}
	for _, p := range s.Parts {
		if p.Kind == definition.KindLaunch {
			if r, ok := launchPackage(p); ok {
				add(r)
			}
			continue
		}
		if p.Binary || p.Text == "" {
			continue
		}
		base := strings.ToLower(p.Name[strings.LastIndex(p.Name, "/")+1:])
		switch {
		case p.Kind == definition.KindFile && base == "package.json":
			for _, r := range manifestPackages(p) {
				add(r)
			}
		case p.Kind == definition.KindFile && strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
			for _, r := range requirementPackages(p) {
				add(r)
			}
		}
		for _, r := range commandPackages(p) {
			add(r)
		}
	}
	return out
}

// launchPackage is the package a launch definition runs, located at its
// package field.
func launchPackage(p definition.Part) (PackageRef, bool) {
	var l Launch
	if json.Unmarshal(p.JSON, &l) != nil || l.Package == "" || l.Ecosystem == "" {
		return PackageRef{}, false
	}
	shown := l.Package
	if l.Version != "" {
		shown += "@" + l.Version
	}
	return PackageRef{Ecosystem: l.Ecosystem, Name: l.Package, Version: l.Version, At: Finding{
		PartKind: p.Kind, PartName: p.Name, Field: "package", End: len(l.Package), Line: 1,
		Evidence: strings.TrimSpace(l.Runner + " " + shown),
	}}, true
}

func at(p definition.Part, start, end int) Finding {
	return Finding{PartKind: p.Kind, PartName: p.Name, Start: start, End: end,
		Line: strings.Count(p.Text[:start], "\n") + 1, Evidence: evidence(p.Text, start, end)}
}

func manifestPackages(p definition.Part) []PackageRef {
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(p.Text), &m) != nil {
		return nil
	}
	var out []PackageRef
	for _, section := range []string{"dependencies", "optionalDependencies", "peerDependencies"} {
		var deps map[string]string
		if json.Unmarshal(m[section], &deps) != nil {
			continue
		}
		for name, spec := range deps {
			if !npmNameRE.MatchString(strings.ToLower(name)) {
				continue
			}
			i := strings.Index(p.Text, `"`+name+`"`)
			if i < 0 {
				continue
			}
			ref := PackageRef{Ecosystem: EcosystemNPM, Name: name, At: at(p, i, i+len(name)+2)}
			ref.At.Field = section
			if v := strings.TrimSpace(spec); exactRE.MatchString(v) {
				ref.Version = strings.TrimPrefix(v, "v")
			}
			out = append(out, ref)
		}
	}
	return out
}

func requirementPackages(p definition.Part) []PackageRef {
	var out []PackageRef
	for _, m := range reqLineRE.FindAllStringSubmatchIndex(p.Text, -1) {
		name := p.Text[m[2]:m[3]]
		if strings.HasPrefix(strings.TrimSpace(p.Text[m[0]:m[1]]), "-") || !pypiNameRE.MatchString(name) {
			continue
		}
		ref := PackageRef{Ecosystem: EcosystemPyPI, Name: name, At: at(p, m[2], m[1])}
		if m[4] >= 0 {
			if v, ok := strings.CutPrefix(strings.TrimSpace(p.Text[m[4]:m[5]]), "=="); ok {
				if v = strings.TrimSpace(v); exactRE.MatchString(v) {
					ref.Version = v
				}
			}
		}
		out = append(out, ref)
	}
	return out
}

// commandPackages reads the arguments of an install or run command, skipping
// flags, and stops at the first word that is not a package: a path, a URL, a
// shell operator, or a word that cannot be a name.
func commandPackages(p definition.Part) []PackageRef {
	var out []PackageRef
	for _, m := range installRE.FindAllStringSubmatchIndex(p.Text, -1) {
		if !inCode(p, m[2]) {
			continue
		}
		tool := strings.Fields(p.Text[m[2]:m[3]])[0]
		eco := EcosystemNPM
		switch tool {
		case "pip", "pip3", "python", "python3", "uv", "uvx", "pipx":
			eco = EcosystemPyPI
		}
		runner := tool == "npx" || tool == "bunx" || tool == "uvx" || strings.HasSuffix(p.Text[m[2]:m[3]], "dlx") || strings.HasSuffix(p.Text[m[2]:m[3]], "run")
		args := p.Text[m[4]:m[5]]
		pos := m[4]
		skipValue := false
		for _, word := range strings.Fields(args) {
			off := strings.Index(p.Text[pos:], word)
			start := pos + off
			pos = start + len(word)
			w := strings.TrimRight(strings.Trim(word, `"'(),`), ".:")
			if skipValue {
				skipValue = false
				continue
			}
			if strings.HasPrefix(w, "-") {
				skipValue = valueFlags[w]
				continue
			}
			if fileLike(w) {
				break
			}
			ref, ok := parseSpec(eco, w)
			if !ok {
				break
			}
			ref.At = at(p, start, start+len(word))
			out = append(out, ref)
			if runner {
				break
			}
		}
	}
	return out
}

// valueFlags take the next word as their value, which is a file, a URL or a
// directory, never a package.
var valueFlags = map[string]bool{
	"-r": true, "--requirement": true, "-c": true, "--constraint": true, "-e": true, "--editable": true,
	"-i": true, "--index-url": true, "--extra-index-url": true, "-t": true, "--target": true,
	"--prefix": true, "--registry": true, "-p": true, "--package": true, "--python": true, "--with": true,
	"-f": true, "--find-links": true, "--cache-dir": true, "--root": true,
}

var fileExts = []string{".txt", ".toml", ".cfg", ".json", ".lock", ".whl", ".tgz", ".gz", ".zip", ".py", ".js", ".ts", ".sh"}

func fileLike(w string) bool {
	if strings.ContainsAny(w, "/\\") && !strings.HasPrefix(w, "@") || w == "." || w == ".." {
		return true
	}
	for _, e := range fileExts {
		if strings.HasSuffix(strings.ToLower(w), e) {
			return true
		}
	}
	return false
}

// inCode is whether a command at pos is one the text tells the agent to run,
// rather than prose about it: in a prose file, inside a code span or fence, or
// a line of its own; in a script, outside a comment.
func inCode(p definition.Part, pos int) bool {
	ls := strings.LastIndexByte(p.Text[:pos], '\n') + 1
	head := strings.TrimLeft(p.Text[ls:pos], " \t>$")
	if !isProse(p.Name) {
		for _, c := range []string{"#", "//", "*", "--", "<!--"} {
			if strings.HasPrefix(head, c) {
				return false
			}
		}
		return true
	}
	if head == "" {
		return true
	}
	if strings.Count(p.Text[ls:pos], "`")%2 == 1 {
		return true
	}
	fences := 0
	for _, line := range strings.Split(p.Text[:ls], "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			fences++
		}
	}
	return fences%2 == 1
}

func parseSpec(eco, w string) (PackageRef, bool) {
	ref := PackageRef{Ecosystem: eco}
	switch eco {
	case EcosystemNPM:
		name, version := w, ""
		if i := strings.LastIndex(w, "@"); i > 0 {
			name, version = w[:i], w[i+1:]
		}
		if !npmNameRE.MatchString(strings.ToLower(name)) || strings.ContainsAny(name, ":") {
			return ref, false
		}
		ref.Name = name
		if exactRE.MatchString(version) {
			ref.Version = strings.TrimPrefix(version, "v")
		}
	case EcosystemPyPI:
		name, version := w, ""
		if i := strings.IndexAny(w, "=<>!~["); i > 0 {
			name = w[:i]
			if v, ok := strings.CutPrefix(w[i:], "=="); ok {
				version = v
			}
		}
		if !pypiNameRE.MatchString(name) {
			return ref, false
		}
		ref.Name = name
		if exactRE.MatchString(version) {
			ref.Version = version
		}
	}
	return ref, true
}
