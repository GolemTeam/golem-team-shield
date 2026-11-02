//go:build !windows

package agentposture

func claudeRegistryPolicy(string) map[string]any { return nil }
