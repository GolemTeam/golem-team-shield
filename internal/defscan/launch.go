package defscan

import (
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/GolemTeam/golem-team-shield/internal/cmdpattern"
)

// Launch is what an MCP server's configured command runs, and nothing else from
// it: the runner, the package or container image it starts, or the host of the
// URL it is reached at. Every other argument and the whole environment are
// left out, because that is where a config keeps its tokens, connection strings
// and paths; what is kept is what a reviewer decides on and what a supply-chain
// check can look up.
type Launch struct {
	Transport string `json:"transport"`
	Runner    string `json:"runner,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Package   string `json:"package,omitempty"`
	Version   string `json:"version,omitempty"`
	Image     string `json:"image,omitempty"`
	URL       string `json:"url,omitempty"`
	// Local is a server run from a file on the machine (node ./server.js): the
	// file's path is the user's, so only the fact is kept.
	Local bool `json:"local,omitempty"`
}

var (
	imageRE = regexp.MustCompile(`^([a-z0-9.-]+(:[0-9]+)?/)?[a-z0-9]+([._/-][a-z0-9]+)*(:[\w][\w.-]{0,127})?(@sha256:[a-f0-9]{64})?$`)

	npxValueFlags    = map[string]bool{"-p": true, "--package": true, "-c": true, "--call": true, "--registry": true, "--cache": true, "--userconfig": true}
	dockerValueFlags = map[string]bool{
		"-e": true, "--env": true, "--env-file": true, "-v": true, "--volume": true, "--mount": true, "--name": true,
		"-p": true, "--publish": true, "--network": true, "--net": true, "-w": true, "--workdir": true, "--entrypoint": true,
		"-u": true, "--user": true, "--platform": true, "--pull": true, "-l": true, "--label": true, "--add-host": true,
		"--cpus": true, "-m": true, "--memory": true, "--hostname": true, "-h": true, "--device": true, "--gpus": true,
		"--cap-add": true, "--cap-drop": true, "--security-opt": true, "--tmpfs": true, "--ulimit": true, "--log-driver": true,
	}
	uvxValueFlags = map[string]bool{"--from": true, "--with": true, "--python": true, "-p": true, "--index": true, "--index-url": true, "--extra-index-url": true}
)

// ParseLaunch is the projection of one configured server: a stdio command and
// its arguments, or a remote server's transport and URL.
func ParseLaunch(transport, command string, args []string, rawURL string) (Launch, bool) {
	if rawURL != "" {
		u, err := url.Parse(rawURL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return Launch{}, false
		}
		if transport == "" || transport == "stdio" {
			transport = "http"
		}
		return Launch{Transport: transport, URL: u.Scheme + "://" + strings.ToLower(u.Host)}, true
	}
	if command == "" {
		return Launch{}, false
	}
	runner := strings.ToLower(path.Base(strings.ReplaceAll(command, `\`, "/")))
	for _, ext := range []string{".exe", ".cmd", ".bat"} {
		runner = strings.TrimSuffix(runner, ext)
	}
	l := Launch{Transport: "stdio", Runner: runner}
	switch runner {
	case "npx", "bunx":
		l.setPackage(EcosystemNPM, firstPackage(args, npxValueFlags, "-p", "--package"))
	case "pnpm", "yarn":
		if len(args) > 0 && args[0] == "dlx" {
			l.setPackage(EcosystemNPM, firstPackage(args[1:], npxValueFlags, "-p", "--package"))
		}
	case "uvx":
		l.setPackage(EcosystemPyPI, firstPackage(args, uvxValueFlags, "--from"))
	case "uv":
		if len(args) > 1 && args[0] == "tool" && args[1] == "run" {
			l.setPackage(EcosystemPyPI, firstPackage(args[2:], uvxValueFlags, "--from"))
		}
	case "pipx":
		if len(args) > 0 && args[0] == "run" {
			l.setPackage(EcosystemPyPI, firstPackage(args[1:], uvxValueFlags, "--spec"))
		}
	case "docker", "podman":
		if len(args) > 0 && args[0] == "run" {
			if img := firstPackage(args[1:], dockerValueFlags); imageRE.MatchString(img) && !cmdpattern.IsSecret(img) {
				l.Image = img
			}
		}
	case "node", "python", "python3", "deno", "bun", "ruby", "java", "go":
		l.Local = len(args) > 0
	default:
		l.Local = strings.ContainsAny(command, `/\`)
		if l.Local {
			l.Runner = ""
		}
	}
	return l, true
}

// firstPackage is the first argument that is not a flag or a flag's value, or
// the value of one of the flags that names the package outright.
func firstPackage(args []string, valueFlags map[string]bool, packageFlags ...string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		for _, pf := range packageFlags {
			if a == pf && i+1 < len(args) {
				return args[i+1]
			}
			if v, ok := strings.CutPrefix(a, pf+"="); ok {
				return v
			}
		}
		if strings.HasPrefix(a, "-") {
			if valueFlags[a] {
				i++
			}
			continue
		}
		return a
	}
	return ""
}

func (l *Launch) setPackage(eco, spec string) {
	if spec == "" || fileLike(spec) || cmdpattern.IsSecret(spec) {
		return
	}
	ref, ok := parseSpec(eco, spec)
	if !ok {
		return
	}
	l.Ecosystem, l.Package, l.Version = eco, NormalizePackage(eco, ref.Name), ref.Version
}
