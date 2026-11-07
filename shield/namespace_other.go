//go:build !linux

package shield

func UserNSRestricted() bool { return false }

func UserNSRestrictable() bool { return false }

func LinuxNamespaces(string) Namespaces { return "" }
