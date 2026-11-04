//go:build !windows

package main

import "errors"

func firewallInstalled() (bool, error) { return false, nil }

func changeFirewall(bool) error { return errors.New("not Windows") }
