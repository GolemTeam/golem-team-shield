//go:build !linux

package main

import "errors"

var errAppArmorNotNeeded = errors.New("not Linux")

func changeAppArmor(bool, string) error { return errors.New("not Linux") }

func appArmorStatus(string) appArmorState { return appArmorState{} }

func runJailLauncher([]string) int { return 126 }
