package shield

// On Linux golem-exec runs each command in its own user and mount namespace,
// which holds the agents' project files and an allowed-hosts network. Where it
// can't make one, neither is held as well: Namespaces says which, for
// `golem-exec status` and `golem doctor`.
type Namespaces string

const (
	// NamespacesOpen: the kernel lets golem-exec make them.
	NamespacesOpen Namespaces = "open"
	// NamespacesProfiled: Ubuntu keeps them from programs AppArmor doesn't
	// name, and golem-exec's profile names a copy of this build.
	NamespacesProfiled Namespaces = "profiled"
	// NamespacesNoProfile: Ubuntu keeps them, and the profile isn't installed.
	NamespacesNoProfile Namespaces = "no_profile"
	// NamespacesStaleProfile: the profile names a copy of another build.
	NamespacesStaleProfile Namespaces = "stale_profile"
	// NamespacesNone: no program may make one here (a container, or user
	// namespaces turned off).
	NamespacesNone Namespaces = "none"
)

// Held says whether commands get their own namespace.
func (n Namespaces) Held() bool { return n == NamespacesOpen || n == NamespacesProfiled }

const (
	// AppArmorStage is the root-owned copy of golem-exec that its AppArmor
	// profile names, and AppArmorProfile the profile.
	AppArmorStage   = "/usr/local/libexec/golem-exec/golem-exec"
	AppArmorProfile = "/etc/apparmor.d/golem-exec"
)
