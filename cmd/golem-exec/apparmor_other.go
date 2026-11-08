//go:build !linux

package main

import "errors"

var errAppArmorNotNeeded = errors.New("not Linux")

func changeAppArmor(bool, string) error { return errors.New("not Linux") }

func runJailLauncher([]string) int { return 126 }

func runJailSetup([]string) int { return 126 }
