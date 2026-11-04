package cmdpattern

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/GolemTeam/golem-team-shield/internal/attacktech"
)

type want struct {
	prog, sub, pattern string
	cat                Category
	attack             []string
}

func (w want) String() string {
	return fmt.Sprintf("{%q %q %q %s %v}", w.prog, w.sub, w.pattern, w.cat, w.attack)
}

func got(c Command) want {
	return want{c.Program, c.Sub, c.Pattern, c.Category, c.Attack}
}

func w(prog, sub, pattern string, cat Category, attack ...string) want {
	if attack == nil {
		attack = []string{}
	}
	return want{prog, sub, pattern, cat, attack}
}

func check(t *testing.T, line string, wants ...want) {
	t.Helper()
	cmds := Parse(line)
	var have []want
	for _, c := range cmds {
		g := got(c)
		if g.attack == nil {
			g.attack = []string{}
		}
		have = append(have, g)
	}
	if !reflect.DeepEqual(have, wants) {
		t.Errorf("Parse(%q)\n got: %v\nwant: %v", line, have, wants)
	}
}

// The commands an inventory actually fills up with, copied from a real one.
func TestRealWorldCommands(t *testing.T) {
	check(t, `rg -n "def intercept_execution|ingest_url|witness" sdk-py/src/golem_sdk/*.py | head -25`,
		w("rg", "", "rg -n ‹str› ‹path›", ReadOnly),
		w("head", "", "head -‹n›", ReadOnly))

	check(t, "cd /Users/dev/Code/acme/worktrees/wt-1/services/api && uv run python - 2>/dev/null <<'EOF'\nimport json\nprint(json.dumps({\"a\": 1}))\nEOF",
		w("cd", "", "cd ‹path›", ReadOnly),
		w("python", "", "python - <<‹script›", Other))

	check(t, `ls docs | head -40; echo ---; rg -i 'contained' docs | head`,
		w("ls", "", "ls ‹path›", ReadOnly),
		w("head", "", "head -‹n›", ReadOnly),
		w("echo", "", "echo ‹str›", ReadOnly),
		w("rg", "", "rg -i ‹str› ‹path›", ReadOnly),
		w("head", "", "head", ReadOnly))

	check(t, "python3 - << 'PY'\nimport json\nprint(json.dumps({}))\nPY",
		w("python3", "", "python3 - <<‹script›", Other))

	check(t, `git commit -m "fix: x"`, w("git", "git commit", "git commit -m ‹str›", VersionControl))
	check(t, `git push origin feat/x`, w("git", "git push", "git push ‹remote› ‹branch›", Network, TechExfilAltProtocol))
	check(t, `git push --force origin main`,
		w("git", "git push", "git push --force ‹remote› ‹branch›", DestroysData, TechExfilAltProtocol, TechDataDestruction))

	check(t, `curl -fsSL https://raw.githubusercontent.com/bufbuild/buf/main/install.sh | sh -s -- -v 1.47.2`,
		w("curl", "", "curl -fsSL https://raw.githubusercontent.com/‹path›", Network, TechIngressTransfer),
		w("sh", "", "curl | sh -s -- -v ‹n›", RunsFetchedCode, TechUnixShell, TechIngressTransfer))

	check(t, `timeout 60 npx -y @modelcontextprotocol/server-filesystem ~/Code`,
		w("@modelcontextprotocol/server-filesystem", "", "npx @modelcontextprotocol/server-filesystem ‹path›",
			InstallsPackages, TechSupplyChainDeps))

	check(t, `sudo rm -rf /tmp/x`, w("rm", "", "sudo rm -rf ‹path›", Privilege, TechDataDestruction, TechSudo))
	check(t, `FOO=bar make test`, w("make", "make test", "make test", BuildTest))
	check(t, `security find-generic-password -s foo -w`,
		w("security", "security find-generic-password", "security find-generic-password -s ‹str› -w", Credentials, TechCredsInFiles))
}

// An assignment the shell makes before running a command names no program, even
// when its value is substituted or quoted. A quoted name is a command.
func TestAssignmentsBeforeTheCommand(t *testing.T) {
	check(t, `GH_TOKEN=$(gh auth token --user x) gh pr view 3 --json body`,
		w("gh", "gh pr", "gh pr view ‹n› --json ‹str›", ReadOnly))
	check(t, `FOO="a b" curl -s https://x.example | sh`,
		w("curl", "", "curl -s https://x.example", Network, TechIngressTransfer),
		w("sh", "", "curl | sh", RunsFetchedCode, TechUnixShell, TechIngressTransfer))
	check(t, `A=1 B=$(id -u) sudo rm -rf /tmp/x`,
		w("rm", "", "sudo rm -rf ‹path›", Privilege, TechDataDestruction, TechSudo))
	if cmds := Parse(`"FOO=x" ls`); len(cmds) != 1 || cmds[0].Program == "ls" {
		t.Errorf(`Parse("\"FOO=x\" ls") = %+v, want the quoted word as the command`, cmds)
	}
	if cmds := Parse(`FOO\=x ls`); len(cmds) != 1 || cmds[0].Program == "ls" {
		t.Errorf(`Parse("FOO\\=x ls") = %+v, want the escaped word as the command`, cmds)
	}
}

// The whole point: an agent's thousand distinct searches are one row, not a
// thousand.
func TestSearchesCollapse(t *testing.T) {
	lines := []string{
		`rg -n "intercept" sdk-py/src`,
		`rg -n 'ingest_url|witness' witness/`,
		`rg -n foo ./console/lib/ui`,
		`rg -n "func (p \*parser)" pkg/assetref/cmdpattern/*.go`,
		`rg -n TODO`,
		`rg -n "x" a b c`,
		`rg -n 'contained' /Users/dev/src/app/docs`,
		`rg -n "a b c" ~/Code/x`,
		`rg -n "^import" --glob '*.dart' console`,
		`rg -n -- '-x' src`,
	}
	patterns := map[string]bool{}
	for _, l := range lines {
		for _, c := range Parse(l) {
			patterns[c.Pattern] = true
			if c.Program != "rg" || c.Category != ReadOnly {
				t.Errorf("%q: got %+v", l, c)
			}
		}
	}
	if len(patterns) > 4 {
		t.Errorf("%d searches made %d patterns, want at most 4: %v", len(lines), len(patterns), patterns)
	}
	for _, l := range lines[:8] {
		if p := Parse(l)[0].Pattern; p != "rg -n ‹str› ‹path›" && p != "rg -n ‹str›" {
			t.Errorf("%q made %q", l, p)
		}
	}
}

func TestCompoundCommands(t *testing.T) {
	check(t, `make build && make test || echo failed; git status &`,
		w("make", "make build", "make build", BuildTest),
		w("make", "make test", "make test", BuildTest),
		w("echo", "", "echo ‹str›", ReadOnly),
		w("git", "git status", "git status", ReadOnly))
	check(t, "go vet ./...\ngo test ./...",
		w("go", "go vet", "go vet ‹path›", BuildTest),
		w("go", "go test", "go test ‹path›", BuildTest))
	check(t, `cat a.txt | sort | uniq -c | sort -rn`,
		w("cat", "", "cat ‹path›", ReadOnly),
		w("sort", "", "sort", ReadOnly),
		w("uniq", "", "uniq -c", ReadOnly),
		w("sort", "", "sort -rn", ReadOnly))
	check(t, `(cd sub && ls) |& tee out.log`,
		w("cd", "", "cd ‹path›", ReadOnly),
		w("ls", "", "ls", ReadOnly),
		w("tee", "", "tee ‹path›", Other))
	check(t, `for f in *.go; do gofmt -l "$f"; done`,
		w("gofmt", "", "gofmt -l $f", BuildTest))
	check(t, `if [ -f x ]; then rm x; fi`,
		w("[", "", "[ -f ‹str›", ReadOnly),
		w("rm", "", "rm ‹path›", Other))
	check(t, `ls # a comment; rm -rf /`, w("ls", "", "ls", ReadOnly))
	check(t, `ls && ls`, w("ls", "", "ls", ReadOnly))
}

func TestWrappersAndRunners(t *testing.T) {
	cases := []struct {
		line     string
		prog     string
		pattern  string
		indirect bool
	}{
		{`nohup nice -n 10 time go build ./...`, "go", "go build ‹path›", false},
		{`stdbuf -oL command ls`, "ls", "ls", false},
		{`env FOO=1 BAR=2 go test ./...`, "go", "go test ‹path›", true},
		{`env -i PATH=/bin make`, "make", "make", true},
		{`bunx prettier --write .`, "prettier", "bunx prettier --write .", true},
		{`uvx ruff@0.6.1 check`, "ruff", "uvx ruff ‹str›", true},
		{`pnpm dlx create-vite@latest app`, "create-vite", "pnpm dlx create-vite ‹str›", true},
		{`uv run --with rich pytest -q`, "pytest", "pytest -q", true},
		{`poetry run python manage.py migrate`, "python", "python ‹path› ‹str›", true},
		{`sh -c "go vet ./..."`, "go", "go vet ‹path›", true},
		{`bash -lc 'make lint'`, "make", "make lint", true},
		{`eval "git status"`, "git", "git status", true},
		{`find . -name '*.go' | xargs gofmt -l`, "gofmt", "gofmt -l", true},
		{`command -v jq`, "command", "command -v ‹str›", false},
		{`exec ./server --port 8080`, "server", "‹repo›/server --port ‹n›", false},
	}
	for _, c := range cases {
		cmds := Parse(c.line)
		last := cmds[len(cmds)-1]
		if last.Program != c.prog || last.Pattern != c.pattern || last.Indirect != c.indirect {
			t.Errorf("%q: got prog=%q pattern=%q indirect=%v, want %q %q %v",
				c.line, last.Program, last.Pattern, last.Indirect, c.prog, c.pattern, c.indirect)
		}
	}
}

func TestSubcommands(t *testing.T) {
	cases := []struct{ line, sub, pattern string }{
		{`git -C /repo --no-pager log --oneline -5`, "git log", "git log -C ‹path› --no-pager --oneline -‹n›"},
		{`gh pr view 123 --json title`, "gh pr", "gh pr view ‹n› --json ‹str›"},
		{`gh api repos/o/r/pulls`, "gh api", "gh api ‹path›"},
		{`docker compose up -d`, "docker compose", "docker compose up -d"},
		{`kubectl -n prod get pods -o wide`, "kubectl get", "kubectl get pods -n ‹str› -o wide"},
		{`aws --profile prod s3 ls s3://bucket/key`, "aws s3", "aws s3 ls --profile ‹str› s3://bucket/‹path›"},
		{`npm run build`, "npm run", "npm run build"},
		{`make -C witness -j8 build`, "make build", "make build -C ‹path› -j‹n›"},
		{`terraform plan -out=tf.plan`, "terraform plan", "terraform plan -out=‹path›"},
		{`brew install jq`, "brew install", "brew install ‹pkg›"},
		{`uv pip install -r requirements.txt`, "uv pip", "uv pip install -r ‹path›"},
		{`flutter pub get`, "flutter pub", "flutter pub get"},
		{`git "status"`, "", "git ‹str›"},
		{`go 1.21`, "", "go ‹n›"},
	}
	for _, c := range cases {
		got := Parse(c.line)[0]
		if got.Sub != c.sub || got.Pattern != c.pattern {
			t.Errorf("%q: got sub=%q pattern=%q, want %q %q", c.line, got.Sub, got.Pattern, c.sub, c.pattern)
		}
	}
}

func TestMasking(t *testing.T) {
	cases := []struct{ line, pattern string }{
		{`git commit -m 'one' -m "two"`, "git commit -m ‹str› -m ‹str›"},
		{`ls --color=always /etc`, "ls --color=‹str› ‹path›"},
		{`curl -o /tmp/x.tgz https://github.com/o/r/archive.tgz?x=1`, "curl -o ‹path› https://github.com/‹path›"},
		{`curl https://user:pw@example.com`, "curl https://example.com"},
		{`curl http://10.0.0.5:8080/api`, "curl http://‹ip›/‹path›"},
		{`ping 192.168.1.1`, "ping ‹ip›"},
		{`git show 3f2a9c1d`, "git show ‹sha›"},
		{`git checkout 5d41402abc4b2a76b9719d911017c592`, "git checkout ‹branch›"},
		{`echo 550e8400-e29b-41d4-a716-446655440000`, "echo ‹uuid›"},
		{`sleep 5`, "sleep ‹n›"},
		{`cat ~/.ssh/id_ed25519.pub`, "cat ~/.ssh/‹path›"},
		{`cat $HOME/.aws/credentials`, "cat ~/.aws/‹path›"},
		{`cat /home/ci/.netrc`, "cat ~/.netrc"},
		{`cat services/api/.env`, "cat ‹path›/.env"},
		{`cat .env.example`, "cat ‹path›"},
		{`export TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyzAB`, "export ‹secret›"},
		{`curl -H "X-Api-Key: 9f8e7d6c5b4a39281706f5e4d3c2b1a0" https://x.io`, "curl -H ‹secret› https://x.io"},
		{`mysql -u root -phunter2secret db`, "mysql -u ‹str› -p‹secret› ‹script›"},
		{`echo "$(date)"`, "echo ‹script›"},
		{`echo "today is $(date)"`, "echo ‹str›"},
		{`echo $(whoami)`, "echo ‹script›"},
		{`ls $DIR`, "ls $DIR"},
		{`printf '%s\n' "$PATH"`, "printf ‹str› $PATH"},
		{`rm a b c`, "rm ‹path›"},
		{`chmod 755 run.sh`, "chmod 755 ‹path›"},
		{`chmod u+s /usr/local/bin/x`, "chmod u+s ‹path›"},
		{`grep -e foo -e bar file`, "grep -e ‹str› -e ‹str› ‹path›"},
		{`ssh deploy@build-1.internal 'uptime'`, "ssh ‹str›@build-1.internal ‹script›"},
		{`scp dump.sql admin@10.1.2.3:/srv/`, "scp ‹path› ‹str›@‹ip›:‹path›"},
		{`git clone git@github.com:acme/app.git`, "git clone git@github.com:‹path›"},
		{`cat <<< "hello"`, "cat <<<‹str›"},
		{`sort < in.txt > out.txt`, "sort <‹path› >‹path›"},
		{`go test ./... 2>&1 | tail -20`, "go test ‹path›"},
		{`kill -9 1234`, "kill -‹n› ‹n›"},
	}
	for _, c := range cases {
		if got := Parse(c.line)[0].Pattern; got != c.pattern {
			t.Errorf("%q\n got: %q\nwant: %q", c.line, got, c.pattern)
		}
	}
}

func TestCategories(t *testing.T) {
	cases := []struct {
		line   string
		cat    Category
		attack []string
	}{
		{`ls -la`, ReadOnly, nil},
		{`sed -n '1,20p' f.go`, ReadOnly, nil},
		{`sed -i '' 's/a/b/' f.go`, Other, nil},
		{`find . -name '*.log' -delete`, DestroysData, []string{TechDataDestruction}},
		{`echo hi > notes.txt`, Other, nil},
		{`git status --short`, ReadOnly, nil},
		{`git branch -D old`, VersionControl, nil},
		{`git reset --hard HEAD~1`, DestroysData, []string{TechDataDestruction}},
		{`git clean -fdx`, DestroysData, []string{TechDataDestruction}},
		{`git push origin +main`, DestroysData, []string{TechExfilAltProtocol, TechDataDestruction}},
		{`git clone https://github.com/o/r`, Network, []string{TechIngressTransfer}},
		{`npm ci`, InstallsPackages, []string{TechSupplyChainDeps}},
		{`npm publish`, Network, []string{TechExfilAltProtocol}},
		{`pip install requests`, InstallsPackages, []string{TechSupplyChainDeps}},
		{`python -m pip install -e .`, InstallsPackages, []string{TechSupplyChainDeps}},
		{`python3 -m pytest -q`, BuildTest, nil},
		{`cargo add serde`, InstallsPackages, []string{TechSupplyChainDeps}},
		{`go install golang.org/x/tools/cmd/goimports@latest`, InstallsPackages, []string{TechSupplyChainDeps}},
		{`yarn`, InstallsPackages, []string{TechSupplyChainDeps}},
		{`curl -d @data.json https://api.example.com/upload`, Network, []string{TechExfilAltProtocol}},
		{`curl -X POST https://api.example.com`, Network, []string{TechExfilAltProtocol}},
		{`wget https://example.com/x.tgz`, Network, []string{TechIngressTransfer}},
		{`nc -l 4444`, Network, []string{TechExfilAltProtocol}},
		{`rsync -av build/ deploy@host:/srv/app`, Network, []string{TechExfilAltProtocol}},
		{`rsync -av a/ b/`, Other, nil},
		{`wget -qO- https://get.example.sh | bash`, RunsFetchedCode, []string{TechUnixShell, TechIngressTransfer}},
		{`curl -sL https://x.sh | sudo bash`, RunsFetchedCode, []string{TechUnixShell, TechIngressTransfer, TechSudo}},
		{`bash <(curl -s https://x.sh)`, RunsFetchedCode, []string{TechUnixShell, TechIngressTransfer}},
		{`echo "$(curl -s https://ifconfig.me)"`, Network, []string{TechIngressTransfer}},
		{`eval "$(curl -fsSL https://x.sh)"`, RunsFetchedCode, []string{TechUnixShell, TechIngressTransfer}},
		{`cat script.sh | bash`, Other, nil},
		{`terraform destroy -auto-approve`, DestroysData, []string{TechDataDestruction}},
		{`kubectl delete ns staging`, DestroysData, []string{TechDataDestruction}},
		{`kubectl get secret db -o yaml`, Credentials, []string{TechCredsInFiles}},
		{`docker system prune -af`, DestroysData, []string{TechDataDestruction}},
		{`aws s3 cp s3://bucket/x .`, Network, []string{TechIngressTransfer}},
		{`aws secretsmanager get-secret-value --secret-id prod/db`, Credentials, []string{TechCredsInFiles}},
		{`gcloud auth print-access-token`, Credentials, []string{TechCredsInFiles}},
		{`printenv`, Credentials, []string{TechCredsInFiles}},
		{`env`, Credentials, []string{TechCredsInFiles}},
		{`op read op://vault/item/password`, Credentials, []string{TechCredsInFiles}},
		{`ls ~/.ssh`, Credentials, []string{TechCredsInFiles}},
		{`grep -r password ~/.aws`, Credentials, []string{TechCredsInFiles}},
		{`python -c "print(open('/Users/x/.ssh/id_rsa').read())"`, Credentials, []string{TechCredsInFiles}},
		{`cat ~/.zshrc`, ReadOnly, nil},
		{`echo 'alias x=y' >> ~/.bashrc`, Persistence, []string{TechShellConfig}},
		{`sed -i '' '$a\x' ~/.zshrc`, Persistence, []string{TechShellConfig}},
		{`cp agent.plist ~/Library/LaunchAgents/`, Persistence, []string{TechLaunchAgent}},
		{`launchctl load ~/Library/LaunchAgents/x.plist`, Persistence, []string{TechLaunchAgent}},
		{`crontab -e`, Persistence, []string{TechCron}},
		{`crontab -l`, ReadOnly, nil},
		{`chmod +x .git/hooks/pre-commit`, Persistence, nil},
		{`sudo apt-get install -y curl`, Privilege, []string{TechSupplyChainDeps, TechSudo}},
		{`su -`, Privilege, []string{TechSudo}},
		{`sudo -i`, Privilege, []string{TechSudo}},
		{`psql -c "select 1"`, Other, nil},
		{`sqlite3 app.db "DROP TABLE users;"`, DestroysData, []string{TechDataDestruction}},
		{`/tmp/payload`, Other, nil},
		{`gh pr list`, ReadOnly, nil},
		{`gh api -X POST repos/o/r/issues -f title=x`, Network, []string{TechExfilAltProtocol}},
		{`gh gist create secrets.txt`, Network, []string{TechExfilAltProtocol}},
		{`brew list`, ReadOnly, nil},
		{`rg curl scripts/`, ReadOnly, nil},
	}
	for _, c := range cases {
		cmds := Parse(c.line)
		if len(cmds) == 0 {
			t.Errorf("%q: no commands", c.line)
			continue
		}
		worst := cmds[0]
		for _, cmd := range cmds[1:] {
			if Worse(worst.Category, cmd.Category) != worst.Category {
				worst = cmd
			}
		}
		attack := worst.Attack
		if len(attack) == 0 {
			attack = nil
		}
		want := append([]string(nil), c.attack...)
		sortStrings(want)
		if worst.Category != c.cat || !reflect.DeepEqual(attack, nilIfEmpty(want)) {
			t.Errorf("%q: got %s %v (%q), want %s %v", c.line, worst.Category, attack, worst.Pattern, c.cat, want)
		}
	}
}

func TestPathClass(t *testing.T) {
	cases := map[string]struct {
		class   PathClass
		pattern string
	}{
		`/tmp/x/run --go`:           {Tmp, "‹tmp›/run --go"},
		`/private/var/folders/a/b`:  {Tmp, "‹tmp›/b"},
		`~/bin/tool`:                {Home, "‹home›/tool"},
		`/Users/dev/go/bin/air`:     {Home, "‹home›/air"},
		`./scripts/dev.sh up`:       {Repo, "‹repo›/dev.sh ‹str›"},
		`/usr/bin/python3 -V`:       {System, "python3 -V"},
		`/opt/homebrew/bin/git log`: {System, "git log"},
		`git log`:                   {OnPath, "git log"},
	}
	for line, c := range cases {
		got := Parse(line)[0]
		if got.PathClass != c.class || got.Pattern != c.pattern {
			t.Errorf("%q: got %q %q, want %q %q", line, got.PathClass, got.Pattern, c.class, c.pattern)
		}
	}
}

func TestSudoIsAMarker(t *testing.T) {
	c := Parse(`sudo -u postgres psql -c "select 1"`)[0]
	if !c.Sudo || c.Program != "psql" || c.Pattern != "sudo psql -c ‹script›" || c.Category != Privilege {
		t.Fatalf("got %+v", c)
	}
	c = Parse(`sudo bash -c 'rm -rf /var/cache/x'`)[0]
	if !c.Sudo || !c.Indirect || c.Pattern != "sudo rm -rf ‹path›" {
		t.Fatalf("got %+v", c)
	}
}

func TestDedupeKeepsDirectOverIndirect(t *testing.T) {
	cmds := Parse(`env X=1 ls; ls`)
	if len(cmds) != 1 || cmds[0].Indirect {
		t.Fatalf("got %+v", cmds)
	}
	cmds = Parse(`env X=1 ls; env Y=2 ls`)
	if len(cmds) != 1 || !cmds[0].Indirect {
		t.Fatalf("got %+v", cmds)
	}
}

func TestTheWitnessSummaryShape(t *testing.T) {
	// witness/pipeline.go collapses whitespace in summary_text, so a heredoc
	// arrives on one line with its delimiter as a word.
	check(t, `cat > /tmp/x.py <<'EOF' import os print(os.getcwd()) EOF && python3 /tmp/x.py`,
		w("cat", "", "cat >‹path› <<‹script›", Other),
		w("python3", "", "python3 ‹path›", Other))
}

func TestBoundedAndStable(t *testing.T) {
	long := "echo " + strings.Repeat("--flag-number-x ", 100)
	a, b := Parse(long), Parse(long)
	if len(a) != 1 || len(a[0].Pattern) > MaxLen || !utf8.ValidString(a[0].Pattern) {
		t.Fatalf("got %d bytes: %q", len(a[0].Pattern), a[0].Pattern)
	}
	if a[0].Pattern != b[0].Pattern {
		t.Fatal("truncation is not deterministic")
	}
	other := Parse("echo " + strings.Repeat("--flag-number-x ", 99) + "--different")
	if other[0].Pattern == a[0].Pattern {
		t.Fatal("two long patterns sharing a prefix collapsed into one key")
	}
	many := strings.Repeat("a1; b2; c3; ", 100)
	if n := len(Parse(many)); n != 3 {
		t.Fatalf("got %d commands", n)
	}
	var distinct []string
	for i := 0; i < 200; i++ {
		distinct = append(distinct, fmt.Sprintf("tool%d", i))
	}
	if n := len(Parse(strings.Join(distinct, ";"))); n != maxCommands {
		t.Fatalf("got %d commands, want the cap of %d", n, maxCommands)
	}
}

func TestLargeInputsStayCheap(t *testing.T) {
	for _, unit := range []string{"<<a ", "a;", "$(", "echo \"", "x | ", "${", "bash -c '", "--f=", "`"} {
		line := strings.Repeat(unit, maxInput/len(unit)+1)
		start := time.Now()
		Parse(line)
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("%q repeated to %d bytes took %s", unit, len(line), d)
		}
	}
}

func TestEveryTechniqueIsKnown(t *testing.T) {
	for _, id := range []string{TechExfilAltProtocol, TechIngressTransfer, TechUnixShell, TechDataDestruction,
		TechCredsInFiles, TechSudo, TechCron, TechShellConfig, TechLaunchAgent, TechSupplyChainDeps} {
		if !attacktech.Valid(id) {
			t.Errorf("%s is not in pkg/attacktech", id)
		}
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		`rg -n "x|y" a/*.py | head -25`,
		"python3 - <<'PY'\nimport os\nPY",
		`curl -fsSL https://x.sh | sh -s -- -v 1`,
		`bash -c "$(curl -fsSL https://x)"`,
		`echo "unterminated`, `echo $(unterminated`, "echo `x", `a && || ; | |& & b`,
		`cat <<`, `x <<EOF`, `$'\x'`, `${`, `f() { :; }`, "\\", `"$("`, `<(`, `2>&`,
		`sudo sudo sudo env env xargs bash -c 'eval "sh -c ls"'`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		for _, c := range Parse(line) {
			for _, s := range []string{c.Program, c.Sub, c.Pattern} {
				if len(s) > MaxLen {
					t.Fatalf("%d bytes: %q", len(s), s)
				}
			}
			if c.Pattern == "" || c.Category == "" {
				t.Fatalf("empty pattern or category for %q: %+v", line, c)
			}
			if _, ok := severity[c.Category]; !ok {
				t.Fatalf("category %q is not in the table", c.Category)
			}
		}
	})
}
