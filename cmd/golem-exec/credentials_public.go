package main

import "github.com/GolemTeam/golem-team-shield/shield"

type credentialSetup struct{}

func (s *shim) prepareCredentials(shield.Policy, string, bool) *credentialSetup { return nil }

func (c *credentialSetup) hosts() []string { return nil }

func (c *credentialSetup) enable(*shield.Proxy) error { return nil }

func (c *credentialSetup) proxyURL(int) string { return "" }

func (c *credentialSetup) env(env []string, _ string, _ *shield.Proxy, _ bool) ([]string, error) {
	return env, nil
}

func (c *credentialSetup) record(*shield.RunRecord, *shield.Proxy) {}
