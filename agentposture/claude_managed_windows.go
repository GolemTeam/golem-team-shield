//go:build windows

package agentposture

import "golang.org/x/sys/windows/registry"

func claudeRegistryPolicy(hive string) map[string]any {
	root := registry.LOCAL_MACHINE
	if hive == "HKCU" {
		root = registry.CURRENT_USER
	}
	k, err := registry.OpenKey(root, claudeRegistryPath, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	raw, _, err := k.GetStringValue("Settings")
	if err != nil || len(raw) > MaxFileBytes {
		return nil
	}
	return parseRegistrySettings(raw)
}
