//go:build !windows

package shield

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// AdminOwned is LoadManaged's trust on macOS and Linux: the file and the
// directory holding it belong to root and no one else can write them, and
// the file is no link, so neither it nor its replacement can come from a
// user.
func AdminOwned(path string) error {
	for _, p := range []string{path, filepath.Dir(path)} {
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symbolic link", p)
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
			return fmt.Errorf("%s is not owned by root: %w", p, errNotAdminOwned)
		}
		if fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s is writable by others: %w", p, errNotAdminOwned)
		}
	}
	return nil
}

var errNotAdminOwned = errors.New("someone other than an administrator can change it")
