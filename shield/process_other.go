//go:build !windows

package shield

func ProtectProcessFromJail() error { return nil }
