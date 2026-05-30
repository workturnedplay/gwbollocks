//go:build windows

// Copyright 2026 workturnedplay
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	//"os/signal"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/workturnedplay/wincoe"
)

var (
	iphlpapiDLL              = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetBestInterface     = iphlpapiDLL.NewProc("GetBestInterface")
	procGetIPForwardTable    = iphlpapiDLL.NewProc("GetIpForwardTable")
	procCreateIPForwardEntry = iphlpapiDLL.NewProc("CreateIpForwardEntry")
	//procSetIpForwardEntry    = iphlpapiDLL.NewProc("SetIpForwardEntry")
	procDeleteIPForwardEntry = iphlpapiDLL.NewProc("DeleteIpForwardEntry")

	procGetIfTable     = iphlpapiDLL.NewProc("GetIfTable")
	procGetIPAddrTable = iphlpapiDLL.NewProc("GetIpAddrTable")
)

// MIB_IPFORWARDROW We define it manually because x/sys/windows does not export the legacy version.
type MIB_IPFORWARDROW struct {
	ForwardDest      uint32
	ForwardMask      uint32
	ForwardPolicy    uint32
	ForwardNextHop   uint32
	ForwardIfIndex   uint32
	ForwardType      uint32
	ForwardProto     uint32
	ForwardAge       uint32
	ForwardNextHopAS uint32
	ForwardMetric1   uint32
	ForwardMetric2   uint32
	ForwardMetric3   uint32
	ForwardMetric4   uint32
	ForwardMetric5   uint32
}

type MIB_IFROW struct {
	WszName         [256]uint16 // This was missing (512 bytes!)
	Index           uint32
	Type            uint32
	Mtu             uint32
	Speed           uint32
	PhysAddrLen     uint32
	PhysAddr        [8]byte
	AdminStatus     uint32
	OperStatus      uint32
	LastChange      uint32
	InOctets        uint32
	InUcastPkts     uint32
	InNUcastPkts    uint32
	InDiscards      uint32
	InErrors        uint32
	InUnknownProtos uint32
	OutOctets       uint32
	OutUcastPkts    uint32
	OutNUcastPkts   uint32
	OutDiscards     uint32
	OutErrors       uint32
	OutQLen         uint32
	DescrLen        uint32
	Descr           [256]byte
}

type MIB_IPFORWARDTABLE struct {
	NumEntries uint32
	Table      [1]MIB_IPFORWARDROW // placeholder for dynamic allocation
}

func getInterfaceGUID(ifIndex uint32) (string, error) {
	size := uint32(15000) // Initial buffer
	for {
		b := make([]byte, size)
		// 1 = AF_INET (IPv4), 0 = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST
		err := windows.GetAdaptersAddresses(windows.AF_INET, 0, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])), &size)
		if err == nil {
			addr := (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0]))
			for addr != nil {
				if addr.IfIndex == ifIndex {
					// Windows returns the GUID as the "AdapterName"
					return windows.BytePtrToString(addr.AdapterName), nil
				}
				addr = addr.Next
			}
			return "", fmt.Errorf("GUID not found for index %d", ifIndex)
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			return "", fmt.Errorf("GetAdaptersAddresses failed, err: %w", err)
		} // else continue doing it again with the new size I guess
	}
}

func clearPersistentGatewayForIndex(ifIndex uint32) error {
	guid, err := getInterfaceGUID(ifIndex)
	if err != nil {
		return fmt.Errorf("failed to get GUID: %w", err)
	}

	path := fmt.Sprintf(`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%s`, guid)
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("failed to open registry key %s, err: %w", path, err)
	}
	defer k.Close()

	// Writing an empty slice to a MULTI_SZ effectively clears the list.
	// If Windows deletes the key entirely, that's actually fine—it means "No GW".
	err = k.SetStringsValue("DefaultGateway", []string{})
	if err != nil {
		return fmt.Errorf("failed to clear DefaultGateway for GUID interface '%s' with indef '%d', err: %w", guid, ifIndex, err)
	}

	// Also clear the metric to prevent "ghost" metrics
	err = k.SetStringsValue("DefaultGatewayMetric", []string{})
	if err != nil {
		return fmt.Errorf("failed to clear DefaultGatewayMetric for GUID interface '%s' with indef '%d', err: %w", guid, ifIndex, err)
	}

	fmt.Printf("Successfully scrubbed Registry for Interface %s with index %d\n", guid, ifIndex)
	return nil
}

// little endian like Windows
func ipv4ToUint32LE(ip string) (uint32, error) {
	var b [4]byte
	n, err := fmt.Sscanf(ip, "%d.%d.%d.%d", &b[0], &b[1], &b[2], &b[3])
	if err != nil || n != 4 {
		return 0, fmt.Errorf("invalid IPv4: %q", ip)
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

// little endian like Windows
func ipv4StringLE(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip&0xFF),
		byte((ip>>8)&0xFF),
		byte((ip>>16)&0xFF),
		byte((ip>>24)&0xFF),
	)
}

type MIB_IPADDRROW struct {
	Addr      uint32
	Index     uint32
	Mask      uint32
	BCastAddr uint32
	ReasmSize uint32
	Unused1   uint16
	Unused2   uint16
}

type MIB_IPADDRTABLE struct {
	NumEntries uint32
	Table      [1]MIB_IPADDRROW // Anchor for the array
}

func listInterfaceIPs() error {
	var size uint32
	procGetIPAddrTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)

	buf := make([]byte, size)
	ret, _, _ := procGetIPAddrTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
	if ret != 0 {
		return fmt.Errorf("GetIpAddrTable failed: %v", ret)
	}

	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	fmt.Printf("\n--- IP Address Table (%d entries) ---\n", num)

	// Each row is 24 bytes (5*4 + 2*2)
	rowSize := uintptr(24)
	offset := uintptr(4)

	for i := uint32(0); i < num; i++ {
		row := (*MIB_IPADDRROW)(unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + offset))

		ip := *(*[4]byte)(unsafe.Pointer(&row.Addr))
		mask := *(*[4]byte)(unsafe.Pointer(&row.Mask))

		fmt.Printf("IF Index %d: IP %d.%d.%d.%d | Mask %d.%d.%d.%d\n",
			row.Index,
			ip[0], ip[1], ip[2], ip[3],
			mask[0], mask[1], mask[2], mask[3])

		offset += rowSize
	}
	fmt.Println("-------------------------------------")
	return nil
}

func listIfIndexes() error {
	var size uint32
	// Use 0 to get the required size first
	ret, _, _ := procGetIfTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	err := syscall.Errno(ret)
	if err != syscall.ERROR_INSUFFICIENT_BUFFER {
		return fmt.Errorf("GetIfTable failed to get size: %d %w", ret, err)
	}

	buf := make([]byte, size)
	ret, _, _ = procGetIfTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
	if ret != 0 {
		err := syscall.Errno(ret)
		return fmt.Errorf("GetIfTable failed: %d %w", ret, err)
	}

	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	// x64 FIX: On 64-bit Windows, there are 4 bytes of padding after 'num'
	// to align the first MIB_IFROW to 8 bytes.
	//offset := uintptr(8) //bad gemini
	// Offset is exactly 4 bytes (the size of 'num')
	offset := uintptr(4)
	rowSize := unsafe.Sizeof(MIB_IFROW{})

	fmt.Printf("Interfaces found: %d\n", num)

	for i := uint32(0); i < num; i++ {
		row := (*MIB_IFROW)(unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + offset))

		// Helper to convert the byte array description to a Go string
		descr := ""
		for j := 0; j < int(row.DescrLen) && j < 256; j++ {
			if row.Descr[j] == 0 {
				break
			}
			descr += string(row.Descr[j])
		}

		fmt.Printf("[%d] Index: %d, MTU: %d, Name: %s\n",
			i, row.Index, row.Mtu, descr)

		offset += rowSize
	}
	return nil
}

// Enumerate routes and check if any default gateway exists on a given interface
func hasDefaultGateway(ifIndex uint32) (bool, uint32, error) {
	var size uint32
	ret, _, callErr := procGetIPForwardTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	err := syscall.Errno(ret)
	if err != syscall.ERROR_INSUFFICIENT_BUFFER {
		return false, 0, fmt.Errorf("procGetIpForwardTable failed to get size: %d %w, err(wrong):%v", ret, err, callErr)
	}
	buf := make([]byte, size)
	ret, _, callErr = procGetIPForwardTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
	if ret != 0 {
		err = syscall.Errno(ret)
		return false, 0, fmt.Errorf("GetIpForwardTable failed, err(correct): %w, err(wrong):%v", err, callErr)
	}

	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	// MIB_IPFORWARDTABLE also has the 4-byte padding on x64
	//offset := uintptr(8)//bad 'gemini 3 thinking'
	offset := uintptr(4) // Reverted to 4 bytes
	rowSize := unsafe.Sizeof(MIB_IPFORWARDROW{})

	for i := uint32(0); i < num; i++ {
		row := (*MIB_IPFORWARDROW)(unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + offset))
		if row.ForwardDest == 0 && row.ForwardMask == 0 && row.ForwardIfIndex == ifIndex {
			return true, row.ForwardNextHop, nil
		}
		offset += rowSize
	}
	return false, 0, nil
}

func colorPrintf(color uint16, msg string, a ...any) {
	//fmt.Printf("\x1b[31m"+msg+"\x1b[0m\n", a...) // XXX: this doesn't work in admin cmd.exe, it's shown raw.
	hStdout := windows.Stdout
	var csbi windows.ConsoleScreenBufferInfo
	if err := windows.GetConsoleScreenBufferInfo(hStdout, &csbi); err != nil {
		panic(fmt.Errorf("GetConsoleScreenBufferInfo failed: %w", err))
	}
	origAttr := csbi.Attributes

	//h2 := uintptr(hStdout)
	//set red
	err := wincoe.SetConsoleTextAttribute(hStdout, color)
	if err != nil {
		panic(err)
	}
	fmt.Printf(msg, a...)
	//restore
	err = wincoe.SetConsoleTextAttribute(hStdout, origAttr)
	if err != nil {
		panic(err)
	}
}

func greenPrintf(msg string, a ...any) {
	colorPrintf(wincoe.FOREGROUND_GREEN|wincoe.FOREGROUND_INTENSITY, msg, a...)
}

func redPrintf(msg string, a ...any) {
	colorPrintf(wincoe.FOREGROUND_RED|wincoe.FOREGROUND_INTENSITY, msg, a...)
}

func cautionPrintf(msg string, a ...any) {
	colorPrintf(wincoe.FOREGROUND_BRIGHT_MAGENTA, msg, a...)
}

// indicates the resulting state was already present, eg. deleting a gw, was already deleted by something else
// but could be an error if this wasn't expected.
func yellowPrintf(msg string, a ...any) {
	colorPrintf(wincoe.FOREGROUND_BRIGHT_YELLOW, msg, a...)
}

func printForwardRow(label string, row MIB_IPFORWARDROW) {
	fmt.Printf("\n--- %s ---\n", label)
	fmt.Printf("Dest:    %08X\n", row.ForwardDest)
	fmt.Printf("Mask:    %08X\n", row.ForwardMask)
	fmt.Printf("NextHop: %08X\n", row.ForwardNextHop)
	fmt.Printf("IfIndex: %d\n", row.ForwardIfIndex)
	fmt.Printf("Type:    %d (3=Direct, 4=Indirect)\n", row.ForwardType)
	fmt.Printf("Proto:   %d (3=NetMgmt, 2=Local)\n", row.ForwardProto)
	fmt.Printf("Policy:  %d (Usually 0)\n", row.ForwardPolicy)
	fmt.Printf("Metrics: [%d, %d, %d, %d, %d]\n",
		row.ForwardMetric1, row.ForwardMetric2, row.ForwardMetric3, row.ForwardMetric4, row.ForwardMetric5)
	fmt.Println("---------------------------")
}

func forceSetDefaultGateway(targetGW, ifIndex uint32) error {
	var size uint32
	procGetIPForwardTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	buf := make([]byte, size)
	ret, _, _ := procGetIPForwardTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)

	var existingRow *MIB_IPFORWARDROW

	var ifMetric uint32 = 0

	if ret == 0 {
		num := *(*uint32)(unsafe.Pointer(&buf[0]))
		offset := uintptr(4)
		rowSize := unsafe.Sizeof(MIB_IPFORWARDROW{})

		for i := uint32(0); i < num; i++ {
			row := (*MIB_IPFORWARDROW)(unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + offset))

			// TRACK METRIC: If this row belongs to our interface, save its metric
			// as a candidate for our new route's metric.
			if ifMetric == 0 && row.ForwardIfIndex == ifIndex {
				ifMetric = row.ForwardMetric1
			}

			// If we find an active default gateway on our target interface...
			if row.ForwardDest == 0 && row.ForwardMask == 0 && row.ForwardIfIndex == ifIndex {
				// Save a clone of the first one we find to use as our "perfect template"
				if existingRow == nil {
					copiedRow := *row
					existingRow = &copiedRow
				}
				// 1. CLEAR THE PATH: Delete the exact route using the OS's own memory struct
				procDeleteIPForwardEntry.Call(uintptr(unsafe.Pointer(row)))
			}
			offset += rowSize
		}
	}

	// FINAL FALLBACK: If we found no routes at all for this interface, use 25
	if ifMetric == 0 || ifMetric == ^uint32(0) {
		ifMetric = 281
		redPrintf("Couldn't find the metric automatically, using metric %d instead.", ifMetric)
	}

	var newRow MIB_IPFORWARDROW

	if existingRow != nil {
		// 2a. Safest approach: Clone the OS parameters and just swap the IP
		//printForwardRow("existingRow before:", *existingRow)
		newRow = *existingRow
		newRow.ForwardNextHop = targetGW
		newRow.ForwardAge = 0
		//printForwardRow("existingRow after:", newRow)
	} else {
		// 2b. Fallback if no gateway existed at all
		newRow = MIB_IPFORWARDROW{
			ForwardDest:    0,
			ForwardMask:    0,
			ForwardPolicy:  0,
			ForwardNextHop: targetGW,
			ForwardIfIndex: ifIndex,
			//Type 4 (Indirect): Used for gateways. It tells Windows "to get to the destination, go talk to this other IP."
			ForwardType:    4,        // MIB_IPROUTE_TYPE_INDIRECT
			ForwardProto:   3,        // MIB_IPPROTO_NETMGMT
			ForwardMetric1: ifMetric, // can't be -1(err 160) or 0(err 87) or 1(err 160)
			/*
					Stick with ^uint32(0) for metrics 2 through 5.
				    Why: In the MIB-II standard used by Windows, -1 (^uint32(0)) explicitly tells the stack "this metric is unused."
			*/
			ForwardMetric2: ^uint32(0), // -1
			ForwardMetric3: ^uint32(0), // -1
			ForwardMetric4: ^uint32(0), // -1
			ForwardMetric5: ^uint32(0), // -1
		}
		//printForwardRow("newRow:", newRow)
	}

	// Add a specific route to the GATEWAY ITSELF first, telling Windows it's "On-Link"
	// Route: [TargetGW] Mask 255.255.255.255 -> Interface Index (No Gateway)
	row := MIB_IPFORWARDROW{
		ForwardDest:    targetGW,
		ForwardMask:    0xFFFFFFFF, // Exact match for the GW IP
		ForwardIfIndex: ifIndex,
		//Type 3 (Direct): Used for the local wire. It tells Windows "the destination is physically right there on the cable; just shout its name (ARP)."
		ForwardType:    3, // MIB_IPROUTE_TYPE_DIRECT (Tell Windows it's on the wire!)
		ForwardProto:   3, // MIB_IPPROTO_NETMGMT
		ForwardNextHop: 0, // No next hop needed for a direct wire route
		// ... metrics ...
		ForwardMetric1: ifMetric,
		ForwardMetric2: ^uint32(0), // -1
		ForwardMetric3: ^uint32(0), // -1
		ForwardMetric4: ^uint32(0), // -1
		ForwardMetric5: ^uint32(0), // -1
	}

	//Remove a theoretical race by setting this to true beforehand
	// if it fails then set it to false
	// if it hits the race then at worst the deletion fails, but it won't exit, it will get to next defer in worst case
	//Same thing for the other bool below.
	removeDirectGWRoute = true // rather fail to delete it than miss deleting it due to race.
	ret, _, _ = procCreateIPForwardEntry.Call(uintptr(unsafe.Pointer(&row)))
	if ret != 0 {
		errNoRet := windows.Errno(ret)
		//continue because it works w/o this anyway!
		if ret == 5010 {
			// if The object already exists. (code 5010)
			yellowPrintf("The entry for on-link gw already existed, err: %v (code %d)", errNoRet, ret)
		} else {
			// if not: The object already exists. (code 5010)
			//then nothing to remove as it failed to add it
			removeDirectGWRoute = false
			redPrintf("CreateIpForwardEntry for gw being on-link failed: %v (code %d)\n", errNoRet, ret)
		}
	}
	// if ret == 0 || ret == 5010 {
	// 	// The object already exists. (code 5010)
	// 	removeDirectGWRoute = true
	// }
	// 3. Create the route
	removeActiveGateway = true // rather fail to delete it than miss deleting it due to race.
	ret, _, _ = procCreateIPForwardEntry.Call(uintptr(unsafe.Pointer(&newRow)))
	if ret != 0 {
		if ret == 5010 {
			// The object already exists. (code 5010)
			redPrintf("Unexpectedly gw already exists(but shoulda been deleted before by our code): %v (code %d)\n", windows.Errno(ret), ret)
			//removeActiveGateway = true
		} else {
			removeActiveGateway = false
		}
		return fmt.Errorf("CreateIpForwardEntry failed: %w (code %d)", windows.Errno(ret), ret)
	}
	// 0 if here
	//removeActiveGateway = true
	return nil
}

var removeActiveGateway, removeDirectGWRoute bool = false, false

// Delete default gateway
func deleteDefaultGateway(gw uint32, ifIndex uint32) error {
	/*
		The reason deleteDefaultGateway worked with Metric1: 1 even if you created it with 281 is because DeleteIpForwardEntry
		is actually quite "fuzzy." It primarily looks for a match on Destination, Mask, NextHop, and IfIndex. As long as those match,
		it usually ignores the metric during deletion unless you have multiple identical routes with different metrics.
	*/
	row := MIB_IPFORWARDROW{
		ForwardDest:    0,
		ForwardMask:    0,
		ForwardNextHop: gw, // Must include gateway IP to identify the route
		ForwardIfIndex: ifIndex,
		ForwardType:    4, // MIB_IPROUTE_TYPE_INDIRECT
		ForwardProto:   3, // MIB_IPPROTO_NETMGMT
		ForwardMetric1: 1,
		ForwardMetric2: ^uint32(0), // CRITICAL: Unused metrics must be -1
		ForwardMetric3: ^uint32(0),
		ForwardMetric4: ^uint32(0),
		ForwardMetric5: ^uint32(0),
	}
	ret, _, err := procDeleteIPForwardEntry.Call(uintptr(unsafe.Pointer(&row)))
	if ret != 0 {
		return fmt.Errorf("DeleteIpForwardEntry failed, ret=%d, err(wrong):'%v', errno(correct):'%w'",
			ret, err, windows.Errno(ret))
	}
	return nil
}

func deleteDirectRoute(targetGW uint32, ifIndex uint32) error {
	row := MIB_IPFORWARDROW{
		ForwardDest:    targetGW,   // The specific IP of the gateway
		ForwardMask:    0xFFFFFFFF, // The /32 mask used during creation
		ForwardNextHop: 0,          // Direct routes have no next hop
		ForwardIfIndex: ifIndex,
		ForwardType:    3, // MIB_IPROUTE_TYPE_DIRECT
		ForwardProto:   3, // MIB_IPPROTO_NETMGMT
		ForwardMetric1: 1, // Metric 1 is usually enough for a match
		ForwardMetric2: ^uint32(0),
		ForwardMetric3: ^uint32(0),
		ForwardMetric4: ^uint32(0),
		ForwardMetric5: ^uint32(0),
	}

	ret, _, _ := procDeleteIPForwardEntry.Call(uintptr(unsafe.Pointer(&row)))

	// 1168 is ERROR_NOT_FOUND. If it's already gone, we don't care.
	if ret != 0 { //&& ret != 1168 {
		return fmt.Errorf("DeleteDirectRoute failed: ret=%d (%w)", ret, windows.Errno(ret))
	}
	return nil
}

// // Get the best interface index for default route
func getDefaultIfIndex() (uint32, error) {
	var ifIndex uint32
	// Use a common IP to find the best local interface
	const commonIP = "8.8.8.8"
	//common, err := parseIPv4ToUint32(commonIP)
	common, err := ipv4ToUint32LE(commonIP)
	if err != nil {
		//FIXME: DRY
		redPrintf("Failed to convert common IP %s into uint32\n", commonIP)
		return 0, fmt.Errorf("failed to convert common IP %s into uint32", commonIP)
	}
	ret, _, err := procGetBestInterface.Call(uintptr(common), uintptr(unsafe.Pointer(&ifIndex)))
	if ret != 0 {
		return 0, fmt.Errorf("GetBestInterface failed: %d %v %w", ret, err, windows.Errno(ret)) //FIXME
	}
	return ifIndex, nil
}

// formatIPv4 writes the dotted IPv4 form of ip (network order)
// into dst and returns the number of bytes written.
//
// dst must be at least 15 bytes long.
func formatIPv4(dst []byte, ip uint32) int {
	_ = dst[14] // bounds check hint

	pos := 0
	pos += writeDecByte(dst[pos:], byte(ip>>24))
	dst[pos] = '.'
	pos++

	pos += writeDecByte(dst[pos:], byte(ip>>16))
	dst[pos] = '.'
	pos++

	pos += writeDecByte(dst[pos:], byte(ip>>8))
	dst[pos] = '.'
	pos++

	pos += writeDecByte(dst[pos:], byte(ip))

	return pos
}

// writeDecByte writes v (0–255) in decimal into dst.
// Returns bytes written (1–3).
func writeDecByte(dst []byte, v byte) int {
	if v >= 100 {
		dst[0] = '0' + v/100
		dst[1] = '0' + (v/10)%10
		dst[2] = '0' + v%10
		return 3
	}
	if v >= 10 {
		dst[0] = '0' + v/10
		dst[1] = '0' + v%10
		return 2
	}
	dst[0] = '0' + v
	return 1
}

type NetworkAdapter struct {
	Index       uint32
	GUID        string
	Description string
	IP          string
}

func getPhysicalAdapters() ([]NetworkAdapter, error) {
	var adapters []NetworkAdapter
	size := uint32(15000)

	for {
		b := make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_INET, windows.GAA_FLAG_SKIP_ANYCAST, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])), &size)
		if err == nil {
			addr := (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0]))
			for addr != nil {
				// 6 = Ethernet, 71 = WiFi, and status must be "Up"
				if (addr.IfType == 6 || addr.IfType == 71) && addr.OperStatus == windows.IfOperStatusUp {
					ipStr := "No IP"
					if addr.FirstUnicastAddress != nil {
						// Extracting the IPv4 string for display
						sa := (*windows.RawSockaddrInet4)(unsafe.Pointer(addr.FirstUnicastAddress.Address.Sockaddr))
						ipStr = fmt.Sprintf("%d.%d.%d.%d", sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3])
					}

					adapters = append(adapters, NetworkAdapter{
						Index:       addr.IfIndex,
						GUID:        windows.BytePtrToString(addr.AdapterName),
						Description: windows.UTF16PtrToString(addr.Description),
						IP:          ipStr,
					})
				}
				addr = addr.Next
			}
			return adapters, nil
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return nil, err
		}
	}
}

func getTargetInterface() (uint32, string, error) {
	// 1. Try the "Easy Way" (works if a gateway exists)
	idx, err := getDefaultIfIndex()
	if err == nil {
		// We still need the GUID for registry cleaning
		guid, _ := getInterfaceGUID(idx)
		return idx, guid, nil
	}

	// 2. Error 1231 happened! The routing table is empty.
	fmt.Println("No existing gateway found, this is better.")
	adapter, err := UserSelectInterface()
	if err != nil {
		return 0, "", fmt.Errorf("failed selecting adapter: %w", err)
	}

	// Return the Index for CreateIpForwardEntry and the GUID for registry cleaning
	return adapter.Index, adapter.GUID, nil
}

func UserSelectInterface() (NetworkAdapter, error) {
	adapters, err := getPhysicalAdapters()
	if err != nil || len(adapters) == 0 {
		return NetworkAdapter{}, fmt.Errorf("could not find any active physical adapters (ie. LAN cable not plugged in)")
	}
	if len(adapters) == 1 {
		return adapters[0], nil
	}

	fmt.Println("Please select an interface manually.")
	fmt.Println("\n--- Available Network Interfaces ---")
	for i, a := range adapters {
		fmt.Printf("[%d] %s\n    IP: %s  (Index: %d)\n", i+1, a.Description, a.IP, a.Index)
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("\nSelect the adapter to use for the Gateway: ")
	input, _ := reader.ReadString('\n')
	choice, _ := strconv.Atoi(strings.TrimSpace(input))

	if choice < 1 || choice > len(adapters) {
		return NetworkAdapter{}, fmt.Errorf("invalid selection")
	}

	return adapters[choice-1], nil
}

const gwFile = "gateway.cfg"

func getWantedGW() (string, error) {
	file, err := os.Open(gwFile)
	if err != nil {
		return "", fmt.Errorf("failed opening file '%s', err:'%w' Create the file and store an IP like 192.168.1.1 on a line. # are comments (inline too)", gwFile, err)
	}
	defer file.Close()

	var foundIPs []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		// 1. Strip comments
		if commentIdx := strings.Index(line, "#"); commentIdx != -1 {
			line = line[:commentIdx]
		}

		// 2. Clean up whitespace
		line = strings.TrimSpace(line)

		// 3. Collect if not empty
		if line != "" {
			foundIPs = append(foundIPs, line)
		}
	}

	// Logic Check
	switch len(foundIPs) {
	case 0:
		return "", fmt.Errorf("error: No gateway IP found in gateway.cfg")
	case 1:
		gatewayIP := foundIPs[0]
		return gatewayIP, nil
	default:
		return "", fmt.Errorf("multiple IP entries found: [%s]. Please ensure only one is active",
			strings.Join(foundIPs, ", "))
	}
}

func onlinkgatewayremoval(targetGW, ifIndex uint32, complainIfFails bool) {
	if removeDirectGWRoute {
		if err := deleteDirectRoute(targetGW, ifIndex); err != nil {
			if errors.Is(err, windows.Errno(1168)) {
				yellowPrintf("Apparently the on-link gateway entry was already removed, possibly by another instance u ran in parallel and exited! err: %v\n", err)
			} else {
				redPrintf("Failed to delete the on-link gateway: %v\n", err)
			}
		} else {
			greenPrintf("on-link direct route to gateway removed\n")
		}
		removeDirectGWRoute = false // Reset for next toggle
	} else if complainIfFails {
		redPrintf("Not removing on-link gateway (wasn't set? run: route print -4)\n")
	}
}

func defaultgatewayremoval(targetGW, ifIndex uint32, complainIfFails bool) {
	if removeActiveGateway {
		if err := deleteDefaultGateway(targetGW, ifIndex); err != nil {
			if errors.Is(err, windows.Errno(1168)) {
				yellowPrintf("Apparently the gateway was already removed, possibly by another instance u ran in parallel and exited! err: %v\n", err)
			} else {
				redPrintf("Failed to delete gateway: %v\n", err)
			}
		} else {
			greenPrintf("Default gateway removed, internet access should be off then.\n")
		}
		removeActiveGateway = false // Reset for next toggle
	} else if complainIfFails {
		redPrintf("Not removing gateway (wasn't set? run: route print -4)\n")
	}
}

var (
	kernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procSetConsoleCtrlHandler = kernel32.NewProc("SetConsoleCtrlHandler")

	globalCleanup func() // Anchor to bridge inside main() to the callback safely
)

// The callback function that Windows calls during shutdown/logoff events.
// Since this utility operates entirely out of the Windows Command Prompt or PowerShell, utilizing SetConsoleCtrlHandler is significantly cleaner.
// It registers a control handler function that directly catches CTRL_SHUTDOWN_EVENT and CTRL_LOGOFF_EVENT sent by Win11 during a restart.
func consoleCtrlHandler(ctrlType uint32) uintptr {
	const (
		CTRL_C_EVENT     = 0
		CTRL_BREAK_EVENT = 1
		//clicked the close button on top right:
		CTRL_CLOSE_EVENT = 2
		//if win11 wants to restart/shutdown:
		CTRL_LOGOFF_EVENT   = 5
		CTRL_SHUTDOWN_EVENT = 6
	)
	switch ctrlType {
	//case windows.CTRL_LOGOFF_EVENT, windows.CTRL_SHUTDOWN_EVENT:
	case CTRL_C_EVENT, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT:
		// We handle ALL terminating events here to ensure the gateway is stripped
		if globalCleanup != nil {
			globalCleanup()
		}
		return 1 // Signal that the event has been handled // Return TRUE to let Windows know we've processed the event
	}
	return 0 // Pass unhandled events back to OS defaults // Pass other events back to Windows defaults
}

func main() {
	// Top-level defer: Executes last! Restored console state guarantees exclusive, clean access here.
	defer func() {
		if !wincoe.WaitAnyKeyIfInteractive() {
			fmt.Println("Didn't wait for keypress due to not an interactive/terminal.")
		}
	}()

	if err := listIfIndexes(); err != nil {
		fmt.Println("Error listing interfaces:", err)
	} else {
		if err := listInterfaceIPs(); err != nil {
			fmt.Println("Error listing interfaces:", err)
		}
	}

	ifIndex, _, err := getTargetInterface() //getDefaultIfIndex()
	if err != nil {
		redPrintf("Cannot get default interface: %v\n", err)
		return
	}

	fmt.Printf("default interface index: %d\n", ifIndex)

	exists, existingGW, err := hasDefaultGateway(ifIndex)
	if err != nil {
		fmt.Println(err)
		return
	}

	if exists {
		fmt.Printf("raw:        0x%08X\n", existingGW)
		redPrintf("Warning: default gateway already exists on this interface: %s\n", ipv4StringLE(existingGW))
	}

	// Example gateway, replace with the “real” GW you want
	wantedGW, err := getWantedGW()
	if err != nil {
		redPrintf("need to know which gw to set: %v", err)
		return
	} else {
		fmt.Printf("Read gw '%s' from file '%s'\n", wantedGW, gwFile)
	}
	targetGW, err := ipv4ToUint32LE(wantedGW)
	//fmt.Printf("targetGW as uint32: %08X\n", targetGW)
	if err != nil {
		redPrintf("Failed to convert wanted gw IP %s into uint32\n", wantedGW)
		return
	}

	//too early, if not admin they won't be able to remove:
	// defer onlinkgatewayremoval(targetGW, ifIndex)
	// defer defaultgatewayremoval(targetGW, ifIndex)

	//ip := *(*[4]byte)(unsafe.Pointer(&targetGW))
	fmt.Printf("The gateway that we want is %s aka 0x%08X\n",
		ipv4StringLE(targetGW), targetGW)

	token := windows.GetCurrentProcessToken()
	//defer token.Close() // Add this, bad 'gemini 3 thinking' lol
	var isAdmin bool = token.IsElevated()
	if !isAdmin {
		redPrintf("Must run as admin to effect changes!\n")
		return
	}

	// if err := clearPersistentGatewayForIndex(ifIndex); err != nil {
	// 	fmt.Println("Failed to delete persistent gateway(ie. the one set in LAN adapter settings, seen by 'route print' under 'Persistent Routes'), err:", err)
	// 	return //FIXME: exit codes!
	// }
	// // Set proper gateway
	// if err := forceSetDefaultGateway(targetGW, ifIndex); err != nil {
	// 	redPrintf("Failed to set gateway: %v\n", err)
	// 	return
	// }

	// // 3. THE WAITING ROOM
	// cautionPrintf("\n>>> Gateway is ACTIVE. Internet is routed.\n")
	// cautionPrintf(">>> Press Ctrl+C to disconnect and cleanup.\n")

	// // Catch Ctrl+C to remove gateway on exit
	// c := make(chan os.Signal, 1)
	// signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	// <-c
	// fmt.Println("\n[!] Shutdown signal received. Cleaning up routes...")
	// // The defers will now trigger as main() finishes after this point.

	// 1. Put Stdin into raw mode so we can capture Ctrl+R instantly (without hitting Enter)
	// We keep ENABLE_PROCESSED_INPUT active so Ctrl+C still sends SIGINT to our channel.
	var oldMode uint32
	if err := windows.GetConsoleMode(windows.Stdin, &oldMode); err == nil {
		//newMode := oldMode &^ (windows.ENABLE_LINE_INPUT | windows.ENABLE_ECHO_INPUT)
		newMode := oldMode &^ (windows.ENABLE_LINE_INPUT | windows.ENABLE_ECHO_INPUT | windows.ENABLE_PROCESSED_INPUT)
		windows.SetConsoleMode(windows.Stdin, newMode)
		//defer windows.SetConsoleMode(windows.Stdin, oldMode) // Restore mode on exit
		defer windows.SetConsoleMode(windows.Stdin, oldMode) // Executes 2nd on exit, restoring cooked console
	}

	var isActive bool

	// 2. Wrap routing logic into an activate closure
	activate := func() {
		if err := clearPersistentGatewayForIndex(ifIndex); err != nil {
			//fmt.Println("Failed to delete persistent gateway...", err)
			fmt.Println("Failed to delete persistent gateway(ie. the one set in LAN adapter settings, seen by 'route print' under 'Persistent Routes'), err:", err)
			return //XXX: yes, we don't wanna continue if this fails
		}
		if err := forceSetDefaultGateway(targetGW, ifIndex); err != nil {
			redPrintf("Failed to set gateway: %v\n", err)
			return
		}
		isActive = true
		cautionPrintf("\n>>> Gateway is ACTIVE. Internet is routed.\n")
	}

	// 3. Wrap cleanup logic into a deactivate closure
	deactivate := func() {
		onlinkgatewayremoval(targetGW, ifIndex, isActive)
		defaultgatewayremoval(targetGW, ifIndex, isActive)

		isActive = false
		yellowPrintf("\n>>> Gateway is INACTIVE. Internet is blocked.\n")
	}

	// Executes 1st on exit: Triggers cleanup if the loop breaks while active.
	// Guarantee cleanup on exit (handles Ctrl+C or normal return)
	defer func() {
		//if isActive {
		deactivate()
		//}
	}()

	// Bind the local closure to the global function holder
	// Bind our local cleanup logic to the package-level anchor
	globalCleanup = deactivate

	// Register the callback with Windows via kernel32.dll
	// Passing '1' as the second argument sets/adds the handler.
	ret, _, err := procSetConsoleCtrlHandler.Call(windows.NewCallback(consoleCtrlHandler), 1)
	//_ = windows.SetConsoleCtrlHandler(windows.NewCallback(consoleCtrlHandler), true)
	if ret == 0 {
		// If ret is 0, the API failed. windows.Errno converts the last-error code into readable text.
		redPrintf("CRITICAL: Failed to register console control handler: %v (errno: %d)\n", err, windows.Errno(ret))
		return
	} else {
		// Just a quiet sanity check confirmation during startup
		fmt.Println("OS termination handler successfully registered.")
	}

	// Initial Activation
	activate()

	// 4. THE WAITING ROOM
	cautionPrintf(">>> Press Ctrl+R to toggle state. Press Ctrl+C to disconnect and exit.\n")

	// // Catch Ctrl+C to remove gateway on exit
	// c := make(chan os.Signal, 1)
	// signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	// Sequential loop on the main goroutine
	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			break
		}
		if buf[0] == 3 { // 0x03 = Ctrl+C
			fmt.Println("\n[!] Ctrl+C detected. Cleaning up routes and restoring terminal...")
			break // Breaking triggers sequential defers naturally
		}
		if buf[0] == 18 { // 0x12 = Ctrl+R
			if isActive {
				deactivate()
			} else {
				activate()
			}
		}
	}

	// for {
	// 	select {
	// 	case <-c:
	// 		fmt.Println("\n[!] Shutdown signal received. Cleaning up routes...")
	// 		return // Exiting main() triggers the `defer` cleanup naturally
	// 	case <-toggleCh:
	// 		if isActive {
	// 			deactivate()
	// 		} else {
	// 			activate()
	// 		}
	// 	}
	// }
}
