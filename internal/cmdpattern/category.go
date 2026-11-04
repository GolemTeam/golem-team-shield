package cmdpattern

import (
	"regexp"
	"strings"
)

// ATT&CK techniques a category can carry.
const (
	TechExfilAltProtocol = "T1048"
	TechIngressTransfer  = "T1105"
	TechUnixShell        = "T1059.004"
	TechDataDestruction  = "T1485"
	TechCredsInFiles     = "T1552.001"
	TechSudo             = "T1548.003"
	TechCron             = "T1053.003"
	TechShellConfig      = "T1546.004"
	TechLaunchAgent      = "T1543.001"
	TechSupplyChainDeps  = "T1195.001"
)

var (
	subPrograms = set("git", "gh", "npm", "pnpm", "yarn", "bun", "go", "cargo", "docker", "kubectl", "helm",
		"aws", "gcloud", "gsutil", "terraform", "make", "brew", "pip", "pip3", "pipx", "uv", "poetry",
		"flutter", "dart", "security", "launchctl", "apt", "apt-get", "gem", "buf", "systemctl")

	globalValueFlags = map[string]map[string]bool{
		"git":       set("-C", "-c", "--git-dir", "--work-tree", "--namespace"),
		"docker":    set("-H", "--host", "--context", "-c", "--config", "-l", "--log-level"),
		"kubectl":   set("-n", "--namespace", "--context", "--kubeconfig", "--cluster", "--user", "-s", "--server"),
		"helm":      set("-n", "--namespace", "--kube-context", "--kubeconfig"),
		"gh":        set("-R", "--repo"),
		"aws":       set("--profile", "--region", "--output", "--endpoint-url", "--query"),
		"gcloud":    set("--project", "--account", "--format", "--configuration", "--region", "--zone"),
		"npm":       set("--prefix", "-w", "--workspace"),
		"pnpm":      set("-C", "--dir", "--filter", "-F"),
		"yarn":      set("--cwd"),
		"go":        set("-C"),
		"cargo":     set("-C", "--manifest-path", "--config", "-Z"),
		"make":      set("-C", "-f", "--file", "--directory", "-I", "--include-dir", "-o", "-W"),
		"uv":        set("--directory", "--project", "--cache-dir", "--config-file"),
		"terraform": set("-chdir"),
		"flutter":   set("-d", "--device-id"),
	}

	thirdLevel = map[string]map[string]bool{
		"gh":        set("*"),
		"aws":       set("*"),
		"gcloud":    set("*"),
		"kubectl":   set("*"),
		"docker":    set("compose", "container", "image", "volume", "network", "system", "buildx", "context", "builder"),
		"git":       set("stash", "remote", "worktree", "submodule", "lfs", "notes", "bisect"),
		"uv":        set("pip", "tool", "python", "cache"),
		"go":        set("mod", "work", "tool"),
		"npm":       set("run", "run-script", "cache", "config"),
		"pnpm":      set("run"),
		"yarn":      set("run", "workspace"),
		"bun":       set("run", "pm"),
		"brew":      set("services", "bundle"),
		"flutter":   set("pub"),
		"dart":      set("pub"),
		"terraform": set("state", "workspace"),
		"helm":      set("repo", "plugin"),
		"pip":       set("cache", "config"),
		"launchctl": set("print"),
		"systemctl": set("--user"),
	}

	valueFlags = map[string]map[string]bool{
		"git": set("-C", "-c", "-m", "-F", "--message", "--file", "--author", "-b", "-B", "-o", "--depth",
			"--format", "--pretty", "-n", "--since", "--until", "-S", "-G", "--grep", "-X", "-s", "--strategy",
			"--onto", "--date", "--max-count", "--branch", "--origin", "--reference", "--template", "--exclude"),
		"rg": set("-e", "-f", "-g", "--glob", "--iglob", "-t", "--type", "-T", "--type-not", "-A", "-B", "-C",
			"-m", "--max-count", "-M", "--max-columns", "-j", "--threads", "--max-depth", "-d", "--sort", "--sortr",
			"-E", "--encoding", "-r", "--replace", "--pre", "--type-add", "--context", "--after-context", "--before-context"),
		"grep": set("-e", "-f", "-A", "-B", "-C", "-m", "--include", "--exclude", "--exclude-dir", "-d", "-D",
			"--context", "--after-context", "--before-context", "--max-count", "--regexp", "--file"),
		"ag": set("-G", "--ignore", "-A", "-B", "-C", "-m", "--file-search-regex"),
		"curl": set("-o", "--output", "-H", "--header", "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
			"--data-ascii", "--json", "-X", "--request", "-u", "--user", "-A", "--user-agent", "-e", "--referer", "-F", "--form",
			"-T", "--upload-file", "-w", "--write-out", "-x", "--proxy", "--connect-timeout", "-m", "--max-time",
			"--retry", "-b", "--cookie", "-c", "--cookie-jar", "--cacert", "--cert", "--key", "-K", "--config",
			"-r", "--range", "--resolve", "--url", "--oauth2-bearer", "-E"),
		"wget": set("-O", "--output-document", "-P", "--directory-prefix", "--header", "--post-data", "--post-file",
			"-U", "--user-agent", "-t", "--tries", "-T", "--timeout", "--user", "--password", "-o", "--output-file"),
		"find": set("-name", "-iname", "-path", "-ipath", "-type", "-maxdepth", "-mindepth", "-newer", "-size",
			"-mtime", "-mmin", "-atime", "-amin", "-ctime", "-user", "-group", "-perm", "-regex", "-iregex",
			"-wholename", "-iwholename", "-fprint", "-printf", "-links", "-inum", "-samefile"),
		"fd":      set("-e", "--extension", "-t", "--type", "-E", "--exclude", "-d", "--max-depth", "-x", "--exec", "-X", "--exec-batch"),
		"head":    set("-n", "-c"),
		"tail":    set("-n", "-c"),
		"sed":     set("-e", "-f", "--expression", "--file"),
		"awk":     set("-F", "-v", "-f"),
		"sort":    set("-k", "-t", "-o", "--key", "--field-separator"),
		"cut":     set("-d", "-f", "-c", "-b"),
		"jq":      set("-f", "--from-file", "--indent", "--arg", "--argjson", "--slurpfile", "--rawfile"),
		"xargs":   set("-n", "-L", "-I", "-P", "-d", "-E", "-s", "-a"),
		"docker":  set("-e", "--env", "-v", "--volume", "-p", "--publish", "--name", "-w", "--workdir", "--network", "-f", "--file", "-t", "--tag", "--platform", "--entrypoint", "-u", "--user", "--env-file", "--mount", "--label", "--build-arg", "--target", "-H", "--context"),
		"kubectl": set("-n", "--namespace", "-l", "--selector", "-o", "--output", "-f", "--filename", "--context", "-c", "--container", "--kubeconfig", "--type", "--image", "--replicas"),
		"helm":    set("-n", "--namespace", "-f", "--values", "--set", "--version", "--kube-context"),
		"gh": set("-R", "--repo", "-t", "--title", "-b", "--body", "-F", "--body-file", "-B", "--base", "-H", "--head",
			"-L", "--limit", "-q", "--jq", "--json", "-l", "--label", "-a", "--assignee", "-m", "--milestone", "-X",
			"--method", "-f", "--raw-field", "--field", "-w", "--workflow", "--template", "-s", "--state", "--search", "-e", "--env"),
		"python":    set("-m", "-c", "-W", "-X"),
		"node":      set("-e", "--eval", "-r", "--require", "-p", "--print", "--import", "--loader"),
		"ruby":      set("-e", "-r", "-I"),
		"perl":      set("-e", "-E", "-M", "-I"),
		"php":       set("-r", "-d", "-f"),
		"deno":      set("--allow-read", "--allow-write", "--allow-net", "--allow-env", "--allow-run", "--config"),
		"ssh":       set("-i", "-p", "-o", "-l", "-F", "-J", "-L", "-R", "-D", "-W", "-b", "-c", "-E", "-e", "-I", "-m", "-O", "-Q", "-S", "-w"),
		"scp":       set("-i", "-P", "-o", "-F", "-J", "-l", "-c", "-S"),
		"rsync":     set("-e", "--rsh", "--exclude", "--include", "--filter", "-f", "--exclude-from", "--include-from", "--files-from", "--chmod", "--log-file", "--rsync-path", "-T", "--temp-dir"),
		"tar":       set("-f", "-C", "--exclude", "-T", "-X", "--directory", "--file"),
		"psql":      set("-c", "--command", "-h", "--host", "-U", "--username", "-d", "--dbname", "-f", "--file", "-p", "--port", "-v", "--set"),
		"mysql":     set("-e", "--execute", "-h", "--host", "-u", "--user", "-p", "-D", "--database", "-P", "--port"),
		"sqlite3":   set("-cmd", "-separator"),
		"npm":       set("--prefix", "-w", "--workspace", "--registry", "--tag"),
		"pnpm":      set("-C", "--dir", "--filter", "-F"),
		"yarn":      set("--cwd"),
		"go":        set("-C", "-o", "-run", "-bench", "-tags", "-ldflags", "-gcflags", "-count", "-timeout", "-p", "-coverprofile", "-covermode", "-exec", "-mod", "-modfile", "-skip", "-parallel", "-benchtime", "-cpu", "-fuzz", "-fuzztime"),
		"cargo":     set("-p", "--package", "--bin", "--example", "--test", "--features", "-F", "--target", "--manifest-path", "-j", "--jobs", "--profile", "-Z"),
		"make":      set("-C", "-f", "--file", "--directory", "-I", "-j", "-o", "-W"),
		"uv":        set("--with", "--python", "-p", "--project", "--directory", "--package", "--env-file", "--index-url", "--extra-index-url", "--from", "-r", "--requirement", "--group", "--extra"),
		"pip":       set("-r", "--requirement", "-i", "--index-url", "--extra-index-url", "-c", "--constraint", "-t", "--target", "-e", "--editable"),
		"security":  set("-s", "-a", "-l", "-c", "-D", "-j", "-r", "-t", "-k", "-P", "-G", "-T"),
		"terraform": set("-var", "-var-file", "-target", "-out", "-state", "-backend-config"),
		"timeout":   set("-s", "--signal", "-k", "--kill-after"),
		"brew":      set("--cask"),
		"gsutil":    set("-m", "-h", "-o"),
		"crontab":   set("-u"),
		"launchctl": set("-w"),
		"op":        set("--vault", "--account", "--fields", "--format"),
	}

	genericValueFlags = set("aws", "gcloud")

	literalValueFlags = map[string]map[string]bool{
		"curl":    set("-X", "--request"),
		"python":  set("-m"),
		"find":    set("-type"),
		"kubectl": set("-o", "--output"),
		"docker":  set("--platform", "--network"),
		"gh":      set("-X", "--method", "-s", "--state"),
	}

	secretValueFlags = map[string]map[string]bool{
		"curl":  set("-u", "--user", "--oauth2-bearer"),
		"wget":  set("--user", "--password"),
		"mysql": set("-p"),
	}

	pathValueFlags = set("-C", "--directory", "--dir", "--cwd", "--prefix", "--file", "--output", "--output-document",
		"--project", "--manifest-path", "-chdir", "--env-file", "--kubeconfig", "--filename", "--git-dir", "--work-tree")
	shortPathFlags = map[string]map[string]bool{
		"make": set("-f"), "docker": set("-f"), "tar": set("-f"), "helm": set("-f"), "psql": set("-f"),
		"kubectl": set("-f"), "curl": set("-o"), "go": set("-o"), "wget": set("-O", "-P"), "sort": set("-o"),
		"rg": set("-f"), "grep": set("-f"),
	}

	codeFlags = set("-c", "-e", "-E", "--eval", "--command", "--execute", "-r", "-cmd", "-p", "--print")
	findExec  = set("-exec", "-execdir", "-ok", "-okdir")

	interpreters = set("python", "ruby", "perl", "php", "node", "deno", "bun", "tsx", "ts-node", "lua",
		"osascript", "bash", "sh", "zsh", "dash", "ksh", "fish", "source", ".")
	sqlClients = set("psql", "mysql", "sqlite3", "duckdb", "clickhouse-client", "clickhouse", "mongosh", "mongo", "cqlsh")
	searchers  = set("rg", "grep", "ag", "ack", "sed", "awk", "jq", "yq")

	fileArgs = set("ls", "cat", "head", "tail", "less", "more", "bat", "wc", "stat", "file", "tree", "du", "cd", "pushd",
		"rm", "rmdir", "cp", "mv", "mkdir", "touch", "ln", "open", "code", "cursor", "vim", "vi", "nvim", "nano", "emacs",
		"diff", "cmp", "realpath", "readlink", "basename", "dirname", "tee", "shred", "unzip", "zip", "gzip", "gunzip",
		"tar", "install", "nl", "od", "xxd", "hexdump", "strings", "sha256sum", "shasum", "md5", "md5sum", "cksum",
		"truncate", "split", "patch", "eza", "exa", "lsd", "fd", "find", "sort", "uniq", "cut", "tr", "comm", "paste", "column")

	readOnly = set("ls", "cat", "head", "tail", "less", "more", "bat", "rg", "grep", "ag", "ack",
		"find", "fd", "wc", "sed", "awk", "pwd", "echo", "printf", "which", "whereis", "type", "jq", "yq",
		"file", "stat", "tree", "du", "df", "diff", "cmp", "sort", "uniq", "cut", "tr", "basename", "dirname",
		"realpath", "readlink", "date", "whoami", "id", "uname", "hostname", "true", "false", "test", "[", "[[",
		"sleep", "cd", "pushd", "popd", "column", "nl", "od", "xxd", "hexdump", "strings", "ps", "lsof", "pgrep",
		"man", "help", "history", "shasum", "sha256sum", "md5", "md5sum", "cksum", "comm", "paste", "fold", "fmt",
		"rev", "tac", "seq", "uptime", "sw_vers", "arch", "nproc", "tokei", "cloc", "eza", "exa", "lsd", "command",
		"wait", "jobs", "top", "htop", "free", "vm_stat", "locale", "tput", "clear", "sha1sum", "b2sum")

	buildTools = set("make", "tsc", "eslint", "prettier", "jest", "vitest", "pytest", "tox", "nox", "ruff", "mypy",
		"black", "isort", "flake8", "pylint", "gofmt", "goimports", "golangci-lint", "staticcheck", "bazel", "bazelisk",
		"gradle", "gradlew", "mvn", "mvnw", "xcodebuild", "swift", "cmake", "ninja", "just", "buf", "protoc",
		"rustc", "rustfmt", "javac", "dotnet", "mix", "rake", "shellcheck", "shfmt",
		"hadolint", "actionlint", "tflint", "biome", "turbo", "nx", "webpack", "vite", "esbuild", "rollup")

	installers = set("gem", "apt", "apt-get", "yum", "dnf", "pacman", "apk", "port", "zypper", "choco", "winget", "conda", "mamba")

	sudoValueFlags  = set("-u", "-g", "-U", "-C", "-h", "-p", "-r", "-t", "-D", "-R", "-T", "--user", "--group")
	xargsValueFlags = set("-n", "-L", "-I", "-P", "-d", "-E", "-s", "-a", "--max-args", "--max-lines", "--max-procs", "--delimiter", "--arg-file")
	uvRunValueFlags = set("--with", "--python", "-p", "--project", "--directory", "--package", "--env-file", "--index-url", "--extra-index-url", "--from", "--group", "--extra", "-E")

	pythonRe = regexp.MustCompile(`^python[0-9.]*$`)
	nodeRe   = regexp.MustCompile(`^node[0-9]*$`)
)

func canonical(prog string) string {
	switch {
	case pythonRe.MatchString(prog):
		return "python"
	case nodeRe.MatchString(prog):
		return "node"
	case prog == "egrep" || prog == "fgrep":
		return "grep"
	case prog == "pip3":
		return "pip"
	case prog == "gawk":
		return "awk"
	}
	return prog
}

func installVerb(prog, verb string) bool {
	switch canonical(prog) {
	case "npm":
		return set("install", "i", "ci", "add", "update", "up", "upgrade", "uninstall", "rm", "remove")[verb]
	case "pnpm", "yarn", "bun":
		return set("install", "i", "add", "update", "up", "upgrade", "remove", "rm")[verb]
	case "pip", "pipx":
		return set("install", "download", "uninstall")[verb]
	case "uv":
		return set("add", "remove", "pip install", "pip uninstall", "tool install")[verb]
	case "cargo":
		return set("install", "add", "remove", "uninstall")[verb]
	case "go":
		return verb == "install" || verb == "get"
	case "brew":
		return set("install", "uninstall", "upgrade", "reinstall", "tap")[verb]
	case "poetry":
		return verb == "add" || verb == "remove"
	}
	return installers[prog] && (verb == "install" || verb == "add" || verb == "remove")
}

func (a *analysis) categorize() (Category, []string) {
	cat, ids := a.base()
	attack := map[string]bool{}
	add := func(c Category, techs ...string) {
		cat = Worse(cat, c)
		for _, t := range techs {
			attack[t] = true
		}
	}
	for _, t := range ids {
		attack[t] = true
	}
	if a.fileRedirect && cat == ReadOnly {
		cat = Other
	}
	if a.credHit {
		add(Credentials, TechCredsInFiles)
	}
	for kind := range a.persistMention {
		if !a.persistWrite[kind] && (cat == ReadOnly || a.prog == "source" || a.prog == ".") {
			continue
		}
		switch kind {
		case kindRC:
			add(Persistence, TechShellConfig)
		case kindLaunch:
			add(Persistence, TechLaunchAgent)
		case kindCron:
			add(Persistence, TechCron)
		case kindGitHooks:
			add(Persistence)
		}
	}
	if a.dropTag {
		add(DestroysData, TechDataDestruction)
	}
	if a.fetchMention {
		if a.interp || a.prog == "eval" {
			a.fetchSubst = true
		} else {
			add(Network, TechIngressTransfer)
		}
	}
	if a.fetchSubst {
		add(RunsFetchedCode, TechUnixShell, TechIngressTransfer)
	}
	if a.sudo {
		add(Privilege, TechSudo)
	}
	return cat, sortedKeys(attack)
}

func (a *analysis) base() (Category, []string) {
	prog, verb := canonical(a.prog), a.verb
	first := strings.SplitN(verb, " ", 2)[0]
	if a.fetchRunner != "" {
		return InstallsPackages, []string{TechSupplyChainDeps}
	}
	switch prog {
	case "git":
		return a.gitCategory()
	case "gh":
		return a.ghCategory()
	case "rm":
		if a.hasShortFlag('r') || a.hasShortFlag('R') || a.hasFlag("--recursive") {
			return DestroysData, []string{TechDataDestruction}
		}
		return Other, nil
	case "shred", "wipefs", "srm":
		return DestroysData, []string{TechDataDestruction}
	case "dd":
		for _, p := range a.pos {
			if strings.HasPrefix(p, "of=") {
				return DestroysData, []string{TechDataDestruction}
			}
		}
		return Other, nil
	case "find":
		switch {
		case a.hasFlag("-delete"):
			return DestroysData, []string{TechDataDestruction}
		case a.hasExec || a.hasFlag("-fprint", "-fprintf", "-fls"):
			return Other, nil
		}
		return ReadOnly, nil
	case "sed":
		if a.hasFlag("--in-place") || a.hasShortFlag('i') || a.hasInPlaceLong() {
			return Other, nil
		}
		return ReadOnly, nil
	case "curl":
		if a.hasFlag("-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--data-ascii", "--json",
			"-F", "--form", "-T", "--upload-file") || a.methodWrites() {
			return Network, []string{TechExfilAltProtocol}
		}
		return Network, []string{TechIngressTransfer}
	case "wget", "aria2c", "http", "https", "fetch":
		if a.hasFlag("--post-data", "--post-file", "--body-data", "--body-file") {
			return Network, []string{TechExfilAltProtocol}
		}
		return Network, []string{TechIngressTransfer}
	case "nc", "ncat", "netcat", "socat", "telnet", "ftp", "sftp", "tftp":
		return Network, []string{TechExfilAltProtocol}
	case "scp", "rsync":
		if a.remote {
			return Network, []string{TechExfilAltProtocol}
		}
		return Other, nil
	case "ssh", "mosh":
		return Network, nil
	case "ping", "dig", "nslookup", "host", "traceroute", "whois", "nmap":
		return Network, nil
	case "sudo", "doas", "su":
		return Privilege, []string{TechSudo}
	case "crontab":
		if a.hasFlag("-l") && len(a.pos) == 0 {
			return ReadOnly, nil
		}
		return Persistence, []string{TechCron}
	case "launchctl":
		switch first {
		case "load", "bootstrap", "enable", "submit", "kickstart":
			return Persistence, []string{TechLaunchAgent}
		case "list", "print", "getenv", "blame", "":
			return ReadOnly, nil
		}
		return Other, nil
	case "security":
		switch {
		case strings.HasPrefix(first, "find-") && strings.HasSuffix(first, "-password"),
			first == "dump-keychain", first == "export", first == "find-certificate", first == "find-identity":
			return Credentials, []string{TechCredsInFiles}
		case strings.HasPrefix(first, "list-") || first == "show-keychain-info":
			return ReadOnly, nil
		}
		return Other, nil
	case "printenv":
		return Credentials, []string{TechCredsInFiles}
	case "env":
		if len(a.pos) == 0 {
			return Credentials, []string{TechCredsInFiles}
		}
		return Other, nil
	case "op", "pass", "gopass", "vault", "bw", "lpass":
		return Credentials, []string{TechCredsInFiles}
	case "npm", "pnpm", "yarn", "bun":
		return a.jsCategory()
	case "pip", "pipx":
		switch {
		case installVerb(a.prog, verb):
			return InstallsPackages, []string{TechSupplyChainDeps}
		case first == "list" || first == "show" || first == "freeze" || first == "check":
			return ReadOnly, nil
		}
		return Other, nil
	case "uv", "poetry":
		switch {
		case installVerb(a.prog, verb), first == "sync", first == "install", verb == "tool install", verb == "pip sync":
			return InstallsPackages, []string{TechSupplyChainDeps}
		case verb == "pip list" || verb == "pip show" || verb == "pip freeze" || first == "tree":
			return ReadOnly, nil
		case first == "venv" || first == "init":
			return Other, nil
		}
		return BuildTest, nil
	case "cargo":
		switch {
		case installVerb(a.prog, verb):
			return InstallsPackages, []string{TechSupplyChainDeps}
		case first == "publish":
			return Network, []string{TechExfilAltProtocol}
		}
		return BuildTest, nil
	case "go":
		switch first {
		case "install", "get":
			return InstallsPackages, []string{TechSupplyChainDeps}
		case "version", "env", "doc", "list":
			return ReadOnly, nil
		}
		return BuildTest, nil
	case "brew":
		switch {
		case first == "uninstall" || first == "remove" || first == "services" || first == "cleanup":
			return Other, nil
		case installVerb(a.prog, verb) || first == "bundle":
			return InstallsPackages, []string{TechSupplyChainDeps}
		case first == "list" || first == "info" || first == "search" || first == "outdated" || first == "doctor" ||
			first == "config" || first == "deps" || first == "leaves" || a.hasFlag("--prefix", "--version"):
			return ReadOnly, nil
		}
		return Other, nil
	case "docker", "podman":
		return a.dockerCategory()
	case "kubectl":
		switch first {
		case "get", "describe":
			if a.mentionsSecrets() {
				return Credentials, []string{TechCredsInFiles}
			}
			return ReadOnly, nil
		case "logs", "top", "explain", "version", "api-resources", "api-versions", "cluster-info", "diff", "auth":
			return ReadOnly, nil
		case "delete":
			return DestroysData, []string{TechDataDestruction}
		}
		return Other, nil
	case "helm":
		switch first {
		case "uninstall", "delete":
			return DestroysData, []string{TechDataDestruction}
		case "list", "ls", "status", "get", "show", "template", "lint", "history", "search", "version":
			return ReadOnly, nil
		case "repo":
			return Network, []string{TechIngressTransfer}
		}
		return Other, nil
	case "terraform", "tofu":
		switch {
		case first == "destroy" || (first == "apply" && a.hasFlag("-destroy")):
			return DestroysData, []string{TechDataDestruction}
		case first == "plan" || first == "validate" || first == "fmt" || first == "init" || first == "providers":
			return BuildTest, nil
		case first == "show" || first == "output" || first == "version" || first == "graph" || verb == "state list" || verb == "state show":
			return ReadOnly, nil
		}
		return Other, nil
	case "aws":
		return a.awsCategory()
	case "gcloud":
		return a.gcloudCategory()
	case "gsutil":
		switch first {
		case "rm", "rb":
			return DestroysData, []string{TechDataDestruction}
		case "cp", "mv", "rsync":
			return a.cloudCopy("gs://")
		case "ls", "cat", "du", "stat":
			return ReadOnly, nil
		}
		return Other, nil
	case "flutter", "dart":
		if verb == "pub get" || verb == "pub add" || verb == "pub upgrade" {
			return InstallsPackages, []string{TechSupplyChainDeps}
		}
		return BuildTest, nil
	case "systemctl":
		if first == "enable" || verb == "--user enable" {
			return Persistence, nil
		}
		return Other, nil
	case "python":
		mod := ""
		if v := a.flagVals["-m"]; len(v) > 0 {
			mod = v[0]
		}
		switch {
		case mod == "pip" && len(a.pos) > 0 && (a.pos[0] == "install" || a.pos[0] == "download"):
			return InstallsPackages, []string{TechSupplyChainDeps}
		case set("pytest", "unittest", "mypy", "ruff", "black", "isort", "flake8", "pylint", "build", "tox", "compileall", "py_compile")[mod]:
			return BuildTest, nil
		case mod == "json.tool":
			return ReadOnly, nil
		}
		return Other, nil
	}
	switch {
	case installers[prog] && (first == "install" || first == "add" || first == "update" || first == "upgrade"):
		return InstallsPackages, []string{TechSupplyChainDeps}
	case buildTools[prog]:
		return BuildTest, nil
	case readOnly[prog]:
		return ReadOnly, nil
	}
	return Other, nil
}

func (a *analysis) hasInPlaceLong() bool {
	for _, f := range a.flags {
		if strings.HasPrefix(f, "--in-place") {
			return true
		}
	}
	return false
}

func (a *analysis) methodWrites() bool {
	for _, m := range append(a.flagVals["-X"], a.flagVals["--request"]...) {
		switch strings.ToUpper(m) {
		case "POST", "PUT", "PATCH":
			return true
		}
	}
	return false
}

func (a *analysis) mentionsSecrets() bool {
	third := ""
	if parts := strings.SplitN(a.verb, " ", 2); len(parts) == 2 {
		third = parts[1]
	}
	if third == "secret" || third == "secrets" {
		return true
	}
	for _, p := range a.pos {
		if p == "secret" || p == "secrets" || strings.HasPrefix(p, "secret/") || strings.HasPrefix(p, "secrets/") {
			return true
		}
	}
	return false
}

func (a *analysis) gitCategory() (Category, []string) {
	verb := a.verb
	first := strings.SplitN(verb, " ", 2)[0]
	switch first {
	case "status", "diff", "log", "show", "rev-parse", "ls-files", "ls-tree", "ls-remote", "blame", "describe",
		"shortlog", "reflog", "grep", "cat-file", "merge-base", "name-rev", "whatchanged", "rev-list", "count-objects",
		"check-ignore", "for-each-ref", "show-ref", "var", "version", "help":
		return ReadOnly, nil
	case "branch":
		if a.hasFlag("-d", "-D", "--delete", "-m", "-M", "--move", "-c", "-C", "-f", "--force", "-u", "--set-upstream-to") {
			return VersionControl, nil
		}
		return ReadOnly, nil
	case "tag":
		if len(a.pos) == 0 || a.hasFlag("-l", "--list") {
			return ReadOnly, nil
		}
		return VersionControl, nil
	case "remote":
		if verb == "remote" || verb == "remote show" || verb == "remote get-url" {
			return ReadOnly, nil
		}
		return VersionControl, nil
	case "stash":
		if verb == "stash list" || verb == "stash show" {
			return ReadOnly, nil
		}
		return VersionControl, nil
	case "worktree":
		if verb == "worktree list" {
			return ReadOnly, nil
		}
		return VersionControl, nil
	case "config":
		if a.hasFlag("--get", "--get-all", "--list", "-l", "--get-regexp") || len(a.pos) == 1 {
			return ReadOnly, nil
		}
		return VersionControl, nil
	case "push":
		force := a.hasFlag("--force", "-f", "--force-with-lease", "--force-if-includes", "--delete", "-d", "--mirror", "--prune")
		for _, p := range a.pos {
			if strings.HasPrefix(p, "+") || strings.HasPrefix(p, ":") {
				force = true
			}
		}
		if force {
			return DestroysData, []string{TechDataDestruction, TechExfilAltProtocol}
		}
		return Network, []string{TechExfilAltProtocol}
	case "reset":
		if a.hasFlag("--hard", "--merge", "--keep") {
			return DestroysData, []string{TechDataDestruction}
		}
		return VersionControl, nil
	case "clean":
		if a.hasShortFlag('f') || a.hasFlag("--force") {
			return DestroysData, []string{TechDataDestruction}
		}
		return VersionControl, nil
	case "clone":
		return Network, []string{TechIngressTransfer}
	case "credential", "credential-store", "credential-osxkeychain":
		return Credentials, []string{TechCredsInFiles}
	}
	return VersionControl, nil
}

func (a *analysis) ghCategory() (Category, []string) {
	parts := strings.SplitN(a.verb, " ", 2)
	first, third := parts[0], ""
	if len(parts) == 2 {
		third = parts[1]
	}
	switch {
	case first == "auth" && third == "token":
		return Credentials, []string{TechCredsInFiles}
	case first == "secret" || (first == "auth" && third == "refresh"):
		return Credentials, []string{TechCredsInFiles}
	case first == "gist" && (third == "create" || third == "edit"),
		first == "release" && (third == "upload" || third == "create"):
		return Network, []string{TechExfilAltProtocol}
	case first == "repo" && third == "clone":
		return Network, []string{TechIngressTransfer}
	case first == "extension" && (third == "install" || third == "upgrade"):
		return InstallsPackages, []string{TechSupplyChainDeps}
	case first == "repo" && third == "delete", first == "release" && third == "delete":
		return DestroysData, []string{TechDataDestruction}
	case first == "api":
		if a.methodWritesGh() {
			return Network, []string{TechExfilAltProtocol}
		}
		return Network, nil
	case set("view", "list", "status", "diff", "checks", "search")[third], first == "status", first == "search", first == "browse":
		return ReadOnly, nil
	}
	return VersionControl, nil
}

func (a *analysis) methodWritesGh() bool {
	for _, m := range append(a.flagVals["-X"], a.flagVals["--method"]...) {
		switch strings.ToUpper(m) {
		case "POST", "PUT", "PATCH", "DELETE":
			return true
		}
	}
	return a.hasFlag("-f", "-F", "--field", "--raw-field", "--input")
}

func (a *analysis) jsCategory() (Category, []string) {
	first := strings.SplitN(a.verb, " ", 2)[0]
	switch {
	case a.verb == "" && (a.prog == "yarn" || a.prog == "bun"):
		return InstallsPackages, []string{TechSupplyChainDeps}
	case installVerb(a.prog, a.verb):
		return InstallsPackages, []string{TechSupplyChainDeps}
	case first == "publish":
		return Network, []string{TechExfilAltProtocol}
	case set("ls", "list", "view", "info", "outdated", "why", "explain", "audit", "search", "root", "bin", "prefix", "whoami")[first]:
		return ReadOnly, nil
	case first == "login" || first == "adduser" || first == "token":
		return Credentials, []string{TechCredsInFiles}
	case first == "link" || first == "unlink" || first == "config" || first == "cache":
		return Other, nil
	}
	return BuildTest, nil
}

func (a *analysis) dockerCategory() (Category, []string) {
	verb := a.verb
	first := strings.SplitN(verb, " ", 2)[0]
	switch {
	case verb == "system prune", verb == "volume rm", verb == "volume prune", verb == "image prune", verb == "container prune", verb == "builder prune":
		return DestroysData, []string{TechDataDestruction}
	case first == "build" || verb == "buildx build" || verb == "compose build":
		return BuildTest, nil
	case first == "push" || verb == "image push":
		return Network, []string{TechExfilAltProtocol}
	case first == "pull" || verb == "image pull" || verb == "compose pull":
		return Network, []string{TechIngressTransfer}
	case first == "login":
		return Credentials, []string{TechCredsInFiles}
	case set("ps", "images", "logs", "inspect", "version", "info", "stats", "top", "history", "port", "diff")[first],
		set("compose ps", "compose logs", "compose config", "image ls", "container ls", "volume ls", "network ls", "context ls", "system df")[verb]:
		return ReadOnly, nil
	}
	return Other, nil
}

func (a *analysis) awsCategory() (Category, []string) {
	parts := strings.SplitN(a.verb, " ", 2)
	service, op := parts[0], ""
	if len(parts) == 2 {
		op = parts[1]
	}
	switch {
	case service == "s3" && (op == "rm" || op == "rb"):
		return DestroysData, []string{TechDataDestruction}
	case service == "s3" && (op == "cp" || op == "mv" || op == "sync"):
		return a.cloudCopy("s3://")
	case service == "s3" && op == "ls":
		return ReadOnly, nil
	case service == "sts" && (op == "get-session-token" || op == "assume-role" || op == "get-federation-token"),
		service == "configure" && (op == "get" || op == "export-credentials"),
		service == "secretsmanager" && op == "get-secret-value",
		service == "ssm" && (op == "get-parameter" || op == "get-parameters"),
		service == "ecr" && op == "get-login-password":
		return Credentials, []string{TechCredsInFiles}
	case strings.HasPrefix(op, "delete-") || strings.HasPrefix(op, "terminate-"):
		return DestroysData, []string{TechDataDestruction}
	case strings.HasPrefix(op, "describe-") || strings.HasPrefix(op, "list-") || strings.HasPrefix(op, "get-"):
		return ReadOnly, nil
	}
	return Other, nil
}

func (a *analysis) gcloudCategory() (Category, []string) {
	joined := a.verb + " " + strings.Join(a.pos, " ")
	switch {
	case strings.Contains(joined, "print-access-token") || strings.Contains(joined, "print-identity-token"),
		strings.HasPrefix(a.verb, "secrets") && strings.Contains(joined, "access"):
		return Credentials, []string{TechCredsInFiles}
	case a.verb == "storage cp" || a.verb == "storage mv" || a.verb == "storage rsync":
		return a.cloudCopy("gs://")
	case a.verb == "storage rm":
		return DestroysData, []string{TechDataDestruction}
	}
	for _, p := range a.pos {
		switch p {
		case "delete":
			return DestroysData, []string{TechDataDestruction}
		case "list", "describe":
			return ReadOnly, nil
		}
	}
	return Other, nil
}

// cloudCopy files an upload to a bucket as exfiltration and a download from one
// as ingress. The destination is the last positional.
func (a *analysis) cloudCopy(scheme string) (Category, []string) {
	if n := len(a.pos); n > 0 && strings.HasPrefix(a.pos[n-1], scheme) {
		return Network, []string{TechExfilAltProtocol}
	}
	return Network, []string{TechIngressTransfer}
}
