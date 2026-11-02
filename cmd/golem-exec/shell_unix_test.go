//go:build !windows

package main

import "testing"

func TestRealShellIsFixedByName(t *testing.T) {
	for in, want := range map[string]string{"golem-zsh": "/bin/zsh", "golem-bash": "/bin/bash", "bash": "/bin/bash", "sh": "/bin/sh", "golem-exec": "/bin/sh"} {
		if got := realShell(in); got != want {
			t.Errorf("%s: got %s", in, got)
		}
	}
}
