//go:build windows

package shield

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The fwpuclnt.dll structures, laid out as the C headers lay them out on
// 64-bit Windows (fwpmtypes.h, fwptypes.h).

type fwpByteBlob struct {
	size uint32
	data *byte
}

type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

type fwpValue0 struct {
	typ   uint32
	value uintptr
}

type fwpRange0 struct {
	low, high fwpValue0
}

type fwpmFilterCondition0 struct {
	fieldKey  windows.GUID
	matchType uint32
	value     fwpValue0
}

type fwpmAction0 struct {
	typ        uint32
	filterType windows.GUID
}

type fwpmSublayer0 struct {
	key          windows.GUID
	display      fwpmDisplayData0
	flags        uint32
	providerKey  *windows.GUID
	providerData fwpByteBlob
	weight       uint16
}

type fwpmFilter0 struct {
	key             windows.GUID
	display         fwpmDisplayData0
	flags           uint32
	providerKey     *windows.GUID
	providerData    fwpByteBlob
	layerKey        windows.GUID
	sublayerKey     windows.GUID
	weight          fwpValue0
	numConditions   uint32
	conditions      *fwpmFilterCondition0
	action          fwpmAction0
	context         [2]uint64
	reserved        *windows.GUID
	filterID        uint64
	effectiveWeight fwpValue0
}

const (
	fwpUint8              = 1
	fwpUint16             = 2
	fwpUint32             = 3
	fwpByteArray16        = 11
	fwpSecurityDescriptor = 14
	fwpRangeType          = 0x102

	fwpMatchEqual = 0
	fwpMatchRange = 5

	fwpActionBlock  = 0x1001
	fwpActionPermit = 0x1002

	fwpmFlagPersistent = 0x1
	rpcAuthnWinNT      = 10

	fwpErrFilterNotFound   = 0x80320003
	fwpErrSublayerNotFound = 0x80320007
	fwpErrNotFound         = 0x80320008
)

var (
	fwpuclnt                = windows.NewLazySystemDLL("fwpuclnt.dll")
	procEngineOpen          = fwpuclnt.NewProc("FwpmEngineOpen0")
	procEngineClose         = fwpuclnt.NewProc("FwpmEngineClose0")
	procTransactionBegin    = fwpuclnt.NewProc("FwpmTransactionBegin0")
	procTransactionCommit   = fwpuclnt.NewProc("FwpmTransactionCommit0")
	procTransactionAbort    = fwpuclnt.NewProc("FwpmTransactionAbort0")
	procSublayerAdd         = fwpuclnt.NewProc("FwpmSubLayerAdd0")
	procSublayerDeleteByKey = fwpuclnt.NewProc("FwpmSubLayerDeleteByKey0")
	procFilterAdd           = fwpuclnt.NewProc("FwpmFilterAdd0")
	procFilterDeleteByKey   = fwpuclnt.NewProc("FwpmFilterDeleteByKey0")
	procFilterGetByKey      = fwpuclnt.NewProc("FwpmFilterGetByKey0")
	procFreeMemory          = fwpuclnt.NewProc("FwpmFreeMemory0")
)

var (
	layerConnectV4   = windows.GUID{Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33, Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}}
	layerConnectV6   = windows.GUID{Data1: 0x4a72393b, Data2: 0x319f, Data3: 0x44bc, Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}}
	condALEUserID    = windows.GUID{Data1: 0xaf043a0a, Data2: 0xb34d, Data3: 0x4f86, Data4: [8]byte{0x97, 0x9c, 0xc9, 0x03, 0x71, 0xaf, 0x6e, 0x66}}
	condRemoteAddr   = windows.GUID{Data1: 0xb235ae9a, Data2: 0x1d64, Data3: 0x49b8, Data4: [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45}}
	condRemotePort   = windows.GUID{Data1: 0xc35a604d, Data2: 0xd22b, Data3: 0x4e1a, Data4: [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b}}
	firewallSublayer = windows.GUID{Data1: 0x5e1d3a7c, Data2: 0x6f2b, Data3: 0x4c11, Data4: [8]byte{0x9a, 0x0d, 0x47, 0x6f, 0x6c, 0x65, 0x6d, 0x01}}
)

const firewallFilters = 6

// firewallFilterKey is the key of the i-th filter, so an install can replace
// them and a removal find them.
func firewallFilterKey(i int) windows.GUID {
	k := firewallSublayer
	k.Data4[7] = byte(0x10 + i)
	return k
}

func fwpCall(p *windows.LazyProc, args ...uintptr) error {
	r, _, _ := p.Call(args...)
	if r != 0 {
		return fwpError(uint32(r))
	}
	return nil
}

// fwpError keeps the HRESULT's number in the message: Windows' text for
// several WFP codes is the same "not supported".
type fwpError uint32

func (e fwpError) Error() string { return fmt.Sprintf("%#x: %v", uint32(e), windows.Errno(e)) }

func openEngine() (windows.Handle, error) {
	var h windows.Handle
	if err := fwpCall(procEngineOpen, 0, rpcAuthnWinNT, 0, 0, uintptr(unsafe.Pointer(&h))); err != nil {
		return 0, err
	}
	return h, nil
}

// InstallFirewall puts the shield's sublayer and filters in place, replacing
// any an earlier install left. It needs administrator rights, and the filters
// persist across reboots until RemoveFirewall.
func InstallFirewall() error { return installFirewall(FirewallSDDL()) }

func installFirewall(sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	sdBytes := unsafe.Slice((*byte)(unsafe.Pointer(sd)), sd.Length())
	engine, err := openEngine()
	if err != nil {
		return err
	}
	defer procEngineClose.Call(uintptr(engine))
	if err := fwpCall(procTransactionBegin, uintptr(engine), 0); err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			procTransactionAbort.Call(uintptr(engine))
		}
	}()
	if err := removeFirewallFrom(engine); err != nil {
		return fmt.Errorf("clear: %w", err)
	}

	name := windows.StringToUTF16Ptr("Golem shield")
	sub := fwpmSublayer0{key: firewallSublayer, flags: fwpmFlagPersistent, weight: 0x7fff,
		display: fwpmDisplayData0{name: name}}
	if err := fwpCall(procSublayerAdd, uintptr(engine), uintptr(unsafe.Pointer(&sub)), 0); err != nil {
		return fmt.Errorf("sublayer: %w", err)
	}

	blob := fwpByteBlob{size: uint32(len(sdBytes)), data: &sdBytes[0]}
	portRange := fwpRange0{
		low:  fwpValue0{typ: fwpUint16, value: uintptr(WindowsProxyPorts[0])},
		high: fwpValue0{typ: fwpUint16, value: uintptr(WindowsProxyPorts[1])},
	}
	loopback6 := [16]byte{15: 1}
	others := []fwpmFilterCondition0{{fieldKey: condALEUserID, matchType: fwpMatchEqual,
		value: fwpValue0{typ: fwpSecurityDescriptor, value: uintptr(unsafe.Pointer(&blob))}}}
	proxy4 := []fwpmFilterCondition0{
		{fieldKey: condRemoteAddr, matchType: fwpMatchEqual, value: fwpValue0{typ: fwpUint32, value: 0x7f000001}},
		{fieldKey: condRemotePort, matchType: fwpMatchRange, value: fwpValue0{typ: fwpRangeType, value: uintptr(unsafe.Pointer(&portRange))}},
	}
	proxy6 := []fwpmFilterCondition0{
		{fieldKey: condRemoteAddr, matchType: fwpMatchEqual, value: fwpValue0{typ: fwpByteArray16, value: uintptr(unsafe.Pointer(&loopback6))}},
		{fieldKey: condRemotePort, matchType: fwpMatchRange, value: fwpValue0{typ: fwpRangeType, value: uintptr(unsafe.Pointer(&portRange))}},
	}
	filters := [firewallFilters]struct {
		layer  windows.GUID
		weight uint8
		action uint32
		conds  []fwpmFilterCondition0
	}{
		{layerConnectV4, 15, fwpActionPermit, others},
		{layerConnectV6, 15, fwpActionPermit, others},
		{layerConnectV4, 14, fwpActionPermit, proxy4},
		{layerConnectV6, 14, fwpActionPermit, proxy6},
		{layerConnectV4, 0, fwpActionBlock, nil},
		{layerConnectV6, 0, fwpActionBlock, nil},
	}
	for i, f := range filters {
		filter := fwpmFilter0{
			key: firewallFilterKey(i), flags: fwpmFlagPersistent, layerKey: f.layer, sublayerKey: firewallSublayer,
			display: fwpmDisplayData0{name: name},
			weight:  fwpValue0{typ: fwpUint8, value: uintptr(f.weight)},
			action:  fwpmAction0{typ: f.action},
		}
		if len(f.conds) > 0 {
			filter.numConditions, filter.conditions = uint32(len(f.conds)), &f.conds[0]
		}
		var id uint64
		if err := fwpCall(procFilterAdd, uintptr(engine), uintptr(unsafe.Pointer(&filter)), 0, uintptr(unsafe.Pointer(&id))); err != nil {
			return fmt.Errorf("filter %d: %w", i, err)
		}
	}
	if err := fwpCall(procTransactionCommit, uintptr(engine)); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	committed = true
	return nil
}

// RemoveFirewall takes the shield's filters and sublayer out; nothing there
// is not an error.
func RemoveFirewall() error {
	engine, err := openEngine()
	if err != nil {
		return err
	}
	defer procEngineClose.Call(uintptr(engine))
	return removeFirewallFrom(engine)
}

func removeFirewallFrom(engine windows.Handle) error {
	for i := 0; i < firewallFilters; i++ {
		k := firewallFilterKey(i)
		if err := fwpCall(procFilterDeleteByKey, uintptr(engine), uintptr(unsafe.Pointer(&k))); err != nil && !notFound(err) {
			return err
		}
	}
	k := firewallSublayer
	if err := fwpCall(procSublayerDeleteByKey, uintptr(engine), uintptr(unsafe.Pointer(&k))); err != nil && !notFound(err) {
		return err
	}
	return nil
}

// FirewallInstalled reports whether the block filter is in place. Reading
// the filters can need rights a user lacks, which the error says.
func FirewallInstalled() (bool, error) {
	engine, err := openEngine()
	if err != nil {
		return false, err
	}
	defer procEngineClose.Call(uintptr(engine))
	k := firewallFilterKey(4)
	var f *fwpmFilter0
	err = fwpCall(procFilterGetByKey, uintptr(engine), uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(&f)))
	if notFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	procFreeMemory.Call(uintptr(unsafe.Pointer(&f)))
	return true, nil
}

func notFound(err error) bool {
	var e fwpError
	if !errors.As(err, &e) {
		return false
	}
	switch uint32(e) {
	case fwpErrFilterNotFound, fwpErrSublayerNotFound, fwpErrNotFound:
		return true
	}
	return false
}
