package shield

import "golang.org/x/sys/windows"

const jailDeniedProcessAccess = windows.PROCESS_VM_READ | windows.PROCESS_VM_WRITE | windows.PROCESS_VM_OPERATION |
	windows.PROCESS_CREATE_THREAD | windows.PROCESS_DUP_HANDLE | windows.PROCESS_SET_INFORMATION |
	windows.PROCESS_SUSPEND_RESUME | windows.PROCESS_CREATE_PROCESS | windows.WRITE_DAC | windows.WRITE_OWNER

// ProtectProcessFromJail denies every jailed command, by the shield's SID in
// its restricting SIDs, the access that would read or change this process's
// memory. A restricted token still passes the user's own check, so without it
// a jailed command could read the keys and tokens the shim and the Golem agent
// hold.
func ProtectProcessFromJail() error {
	sid, err := windows.StringToSid(ShieldSIDString())
	if err != nil {
		return err
	}
	proc := windows.CurrentProcess()
	sd, err := windows.GetSecurityInfo(proc, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: jailDeniedProcessAccess,
		AccessMode:        windows.DENY_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_UNKNOWN,
			TrusteeValue: windows.TrusteeValueFromSID(sid)},
	}}, dacl)
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(proc, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
