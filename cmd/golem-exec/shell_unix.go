//go:build !windows

package main

import (
	"os"
	"strings"
)

// realShell is fixed by name, never looked up on PATH: the jail is only as
// good as the binary it wraps. A distribution that keeps the shell only in
// /usr/bin gets that one.
func realShell(invoked string) string {
	name := "sh"
	switch {
	case strings.Contains(invoked, "zsh"):
		name = "zsh"
	case strings.Contains(invoked, "bash"):
		name = "bash"
	}
	for _, dir := range []string{"/bin/", "/usr/bin/"} {
		if _, err := os.Stat(dir + name); err == nil {
			return dir + name
		}
	}
	return "/bin/" + name
}
