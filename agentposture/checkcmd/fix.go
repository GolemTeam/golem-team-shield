package checkcmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/GolemTeam/golem-team-shield/agentposture"
	"github.com/GolemTeam/golem-team-shield/internal/jsonobject"
)

// ExitRolledBack is -fix -yes having put every file back because the result
// was worse than what it started from.
const ExitRolledBack = 4

var errChanged = errors.New("changed since the plan was made")

func runFix(out, stderr io.Writer, o Options, apply bool) int {
	env := agentposture.DefaultEnv()
	if o.Env != nil {
		env = o.Env()
	}
	return fixWith(out, stderr, o, env, agentposture.PlanFixes(env), apply, time.Now())
}

func fixWith(out, stderr io.Writer, o Options, env agentposture.Env, plan agentposture.FixPlan, apply bool, now time.Time) int {
	writePlan(out, plan)
	if len(plan.Files) == 0 {
		if len(plan.Skipped) > 0 {
			fmt.Fprintln(out, "Nothing for -fix to change. The findings left alone above need changing by hand.")
			return 0
		}
		fmt.Fprintln(out, "Nothing in your own agent settings for -fix to change.")
		return 0
	}
	if !apply {
		fmt.Fprintf(out, "Dry run: nothing was changed. To make these changes: %s -fix -yes\n", o.Name)
		return 0
	}
	before := o.Machine()
	dir, err := backUp(env.Home, plan, now)
	if err != nil {
		fmt.Fprintln(stderr, o.Name+": could not back up the files, so nothing was changed: "+reason(err))
		return 1
	}
	shown := agentposture.DisplayHome(env.Home, dir)
	var done []agentposture.FileFix
	for _, f := range plan.Files {
		if err := applyFile(f); err != nil {
			fmt.Fprintf(stderr, "%s: could not change %s: %s\n", o.Name, f.Location, reason(err))
			return restoreAll(out, stderr, o, done, shown, "", 1)
		}
		done = append(done, f)
	}
	why := unparsed(plan.Files)
	after := o.Machine()
	if why == "" {
		why = worse(before, after)
	}
	if why != "" {
		return restoreAll(out, stderr, o, done, shown, why, ExitRolledBack)
	}
	b, a := agentposture.Score(before), agentposture.Score(after)
	fmt.Fprintf(out, "Changed %d %s. The originals are in %s.\n", len(done), plural(len(done), "file", "files"), shown)
	if a.Grade != "" {
		fmt.Fprintf(out, "Grade: %s (%d) -> %s (%d).\n", b.Grade, b.Score, a.Grade, a.Score)
	}
	fmt.Fprintln(out, "Restart your agents: some read their settings only when they start.")
	return 0
}

func restoreAll(out, stderr io.Writer, o Options, done []agentposture.FileFix, dir, why string, code int) int {
	failed := false
	for i := len(done) - 1; i >= 0; i-- {
		if err := restoreFile(done[i]); err != nil {
			failed = true
			fmt.Fprintf(stderr, "%s: could not put back %s (%s): its original is in %s\n", o.Name, done[i].Location, reason(err), dir)
		}
	}
	if failed {
		return 1
	}
	if why != "" {
		fmt.Fprintf(out, "Rolled back: %s. Every file is as it was; the copies are in %s.\n", why, dir)
	} else if len(done) > 0 {
		fmt.Fprintln(out, "Every file changed so far is back as it was.")
	}
	return code
}

func reason(err error) string {
	switch {
	case errors.Is(err, errChanged):
		return "it " + errChanged.Error() + "; run it again"
	case errors.Is(err, os.ErrPermission):
		return "permission denied (an agent's jail refuses writes to its settings: run this from your own terminal)"
	}
	return fmt.Sprintf("an error of type %T", err)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func writePlan(out io.Writer, plan agentposture.FixPlan) {
	for _, f := range plan.Files {
		fmt.Fprintln(out, f.Location)
		for _, c := range f.Changes {
			fmt.Fprintln(out, "  - "+c)
		}
		if f.NewMode != f.OldMode {
			fmt.Fprintf(out, "  permissions %04o -> %04o\n", f.OldMode, f.NewMode)
		}
		if d := f.Diff(); d != "" {
			for _, line := range strings.Split(strings.TrimSuffix(d, "\n"), "\n") {
				fmt.Fprintln(out, "  "+line)
			}
		}
		fmt.Fprintln(out)
	}
	seen := map[string]bool{}
	var left []string
	for _, s := range plan.Skipped {
		line := fmt.Sprintf("  %s (%s): %s", s.Item.Location, s.Item.Check, s.Reason)
		if !seen[line] {
			seen[line] = true
			left = append(left, line)
		}
	}
	if len(left) > 0 {
		fmt.Fprintln(out, "Left alone:")
		for _, l := range left {
			fmt.Fprintln(out, l)
		}
		fmt.Fprintln(out)
	}
}

type manifestEntry struct {
	Path   string `json:"path"`
	Mode   string `json:"mode"`
	Backup string `json:"backup,omitempty"`
}

// backUp copies each file whose contents change into a new folder under
// ~/.golem, which a jailed agent can neither read nor write, so an agent
// cannot copy a risky setting back. A file whose permissions alone change is
// only listed, so no second copy of a credential is made.
func backUp(home string, plan agentposture.FixPlan, now time.Time) (string, error) {
	root := filepath.Join(home, ".golem", "check-backups")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	stamp := now.UTC().Format("20060102T150405Z")
	dir := filepath.Join(root, stamp)
	for i := 2; ; i++ {
		err := os.Mkdir(dir, 0o700)
		if err == nil {
			break
		}
		if !os.IsExist(err) {
			return "", err
		}
		dir = filepath.Join(root, fmt.Sprintf("%s-%d", stamp, i))
	}
	var manifest []manifestEntry
	for _, f := range plan.Files {
		e := manifestEntry{Path: f.Path, Mode: fmt.Sprintf("%04o", f.OldMode)}
		if f.Old != nil {
			cur, err := os.ReadFile(f.Path)
			if err != nil {
				return "", err
			}
			if !bytes.Equal(cur, f.Old) {
				return "", fmt.Errorf("%s: %w", f.Location, errChanged)
			}
			e.Backup = backupName(home, f.Path)
			dst := filepath.Join(dir, e.Backup)
			if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
				return "", err
			}
			if err := os.WriteFile(dst, f.Old, 0o600); err != nil {
				return "", err
			}
		}
		manifest = append(manifest, e)
	}
	b, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", err
	}
	return dir, os.WriteFile(filepath.Join(dir, "manifest.json"), append(b, '\n'), 0o600)
}

func backupName(home, path string) string {
	if rel, err := filepath.Rel(home, path); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return rel
	}
	return filepath.Join("_root", strings.TrimPrefix(path, filepath.VolumeName(path)))
}

func applyFile(f agentposture.FileFix) error {
	if f.Old == nil {
		info, err := os.Lstat(f.Path)
		if err != nil {
			return err
		}
		if info.Mode().Perm() != f.OldMode || !info.Mode().IsRegular() {
			return errChanged
		}
		return os.Chmod(f.Path, f.NewMode)
	}
	cur, err := os.ReadFile(f.Path)
	if err != nil {
		return err
	}
	if !bytes.Equal(cur, f.Old) {
		return errChanged
	}
	return writeAtomic(f.Path, f.New, f.NewMode)
}

func restoreFile(f agentposture.FileFix) error {
	if f.Old == nil {
		return os.Chmod(f.Path, f.OldMode)
	}
	return writeAtomic(f.Path, f.Old, f.OldMode)
}

// writeAtomic renames a finished temp file over path, so an agent reading its
// settings mid-write sees the old file or the new one, never half of one.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".golem-fix-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func unparsed(files []agentposture.FileFix) string {
	for _, f := range files {
		if f.Old == nil {
			continue
		}
		b, err := os.ReadFile(f.Path)
		if err != nil || !bytes.Equal(b, f.New) {
			return f.Location + " does not read back as written"
		}
		if f.Format == "json" {
			if _, err := jsonobject.Parse(b); err != nil {
				return f.Location + " no longer parses"
			}
		}
	}
	return ""
}

var gradeOrder = map[string]int{"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}

func worse(before, after agentposture.Result) string {
	b, a := agentposture.Score(before), agentposture.Score(after)
	if a.Score < b.Score {
		return fmt.Sprintf("the score went down, from %d to %d", b.Score, a.Score)
	}
	if gb, ok := gradeOrder[b.Grade]; ok {
		if ga, ok := gradeOrder[a.Grade]; ok && ga > gb {
			return fmt.Sprintf("the grade went down, from %s to %s", b.Grade, a.Grade)
		}
	}
	key := func(it agentposture.Item) string {
		return strings.Join([]string{it.Client, it.Check, it.Location, it.Subject, it.Setting, it.Severity}, "\x00")
	}
	had := map[string]bool{}
	for _, it := range before.Items {
		had[key(it)] = true
	}
	for _, it := range after.Items {
		if it.Area != agentposture.AreaProtections && agentposture.Rank(it.Severity) <= agentposture.Rank(agentposture.Suspicious) && !had[key(it)] {
			return fmt.Sprintf("a new %s finding appeared (%s %s in %s)", it.Severity, it.Client, it.Check, it.Location)
		}
	}
	return ""
}
