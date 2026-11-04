package main

import "github.com/GolemTeam/golem-team-shield/shield"

func firewallInstalled() (bool, error) { return shield.FirewallInstalled() }

func changeFirewall(install bool) error {
	if install {
		return shield.InstallFirewall()
	}
	return shield.RemoveFirewall()
}
