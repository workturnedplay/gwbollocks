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
	//"log"
	//"math/bits"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	iphlpapiDLL              = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetBestInterface     = iphlpapiDLL.NewProc("GetBestInterface")
	procGetIpForwardTable    = iphlpapiDLL.NewProc("GetIpForwardTable")
	procCreateIpForwardEntry = iphlpapiDLL.NewProc("CreateIpForwardEntry")
	procSetIpForwardEntry    = iphlpapiDLL.NewProc("SetIpForwardEntry")
	procDeleteIpForwardEntry = iphlpapiDLL.NewProc("DeleteIpForwardEntry")

	procGetIfTable     = iphlpapiDLL.NewProc("GetIfTable")
	procGetIpAddrTable = iphlpapiDLL.NewProc("GetIpAddrTable")
)

// We define it manually because x/sys/windows does not export the legacy version.
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

// Corrected legacy MIB_IFROW
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
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return "", err
		}
	}
}

func clearPersistentGatewayForIndex(ifIndex uint32) error {
	guid, err := getInterfaceGUID(ifIndex)
	if err != nil {
		return fmt.Errorf("failed to get GUID: %v", err)
	}

	path := fmt.Sprintf(`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%s`, guid)
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	// Writing an empty slice to a MULTI_SZ effectively clears the list.
	// If Windows deletes the key entirely, that's actually fine—it means "No GW".
	err = k.SetStringsValue("DefaultGateway", []string{})
	if err != nil {
		return fmt.Errorf("failed to clear DefaultGateway: %v", err)
	}

	// Also clear the metric to prevent "ghost" metrics
	_ = k.SetStringsValue("DefaultGatewayMetric", []string{})

	fmt.Printf("Successfully scrubbed Registry for Interface %s\n", guid)
	return nil
}

// // Convert IPv4 string to uint32 in network byte order
// func ipv4ToUint32(ip string) uint32 {
// 	var b [4]byte
// 	fmt.Sscanf(ip, "%d.%d.%d.%d", &b[0], &b[1], &b[2], &b[3])
// 	return binary.LittleEndian.Uint32(b[:])
// }

// Convert IPv4 string to uint32 in network byte order
// fixed by Gemini 3 Thinking
//
//	func ipv4ToUint32(ip string) uint32 {
//		var b [4]byte
//		fmt.Sscanf(ip, "%d.%d.%d.%d", &b[0], &b[1], &b[2], &b[3])
//		// CRITICAL: Networking is Big Endian
//		return binary.BigEndian.Uint32(b[:]) // Change to BigEndian
//	}

// // Convert IPv4 string to uint32 in a way that produces Network Byte Order in memory
//
//	func ipv4ToUint32(ip string) uint32 {
//		var b [4]byte
//		fmt.Sscanf(ip, "%d.%d.%d.%d", &b[0], &b[1], &b[2], &b[3])
//		// Use LittleEndian so that b[0] (192) ends up at the lowest memory address
//		return binary.LittleEndian.Uint32(b[:])
//	}
//
//	func ipv4ToUint32(ip string) uint32 {
//		var b [4]byte
//		fmt.Sscanf(ip, "%d.%d.%d.%d", &b[0], &b[1], &b[2], &b[3])
//		return uint32(b[0])<<24 |
//			uint32(b[1])<<16 |
//			uint32(b[2])<<8 |
//			uint32(b[3])
//		//192.168.1.1 → 0xC0A80101
//		//which matches the API’s documented expectation.
//	}
//

// // parseIPv4ToUint32 converts dotted IPv4 to a uint32 in network order(aka big endian).
// // No allocations. Strict validation. Hot-path safe.
// func parseIPv4ToUint32(ipv4 string) (uint32, error) {
// 	if len(ipv4) < 7 || len(ipv4) > 15 { // 0.0.0.0 .. 255.255.255.255
// 		return 0, fmt.Errorf("invalid IPv4 length")
// 	}

// 	var parts [4]uint32
// 	part := 0
// 	var val uint32
// 	digits := 0

// 	for i := 0; i < len(ipv4); i++ {
// 		c := ipv4[i]

// 		switch {
// 		case c >= '0' && c <= '9':
// 			val = val*10 + uint32(c-'0')
// 			if val > 255 {
// 				return 0, fmt.Errorf("octet out of range")
// 			}
// 			digits++
// 			if digits > 3 {
// 				return 0, fmt.Errorf("octet too long")
// 			}

// 		case c == '.':
// 			if digits == 0 {
// 				return 0, fmt.Errorf("empty octet")
// 			}
// 			if part >= 3 {
// 				return 0, fmt.Errorf("too many octets")
// 			}
// 			parts[part] = val
// 			part++
// 			val = 0
// 			digits = 0

// 		default:
// 			return 0, fmt.Errorf("invalid character in IPv4")
// 		}
// 	}

// 	// finalize last octet
// 	if part != 3 || digits == 0 {
// 		return 0, fmt.Errorf("invalid IPv4 format")
// 	}
// 	parts[3] = val

// 	// network-order numeric value (contract-correct)
// 	return (parts[0] << 24) |
// 		(parts[1] << 16) |
// 		(parts[2] << 8) |
// 		(parts[3]), nil
// }

// // big endian
// func ipv42String(ip uint32) string {
// 	return fmt.Sprintf("%d.%d.%d.%d",
// 		byte(ip),
// 		byte(ip>>8),
// 		byte(ip>>16),
// 		byte(ip>>24),
// 	)
// }

// // big endian
// func ipv4StringToUint32(ip string) (uint32, error) {
// 	var b [4]byte
// 	n, err := fmt.Sscanf(ip, "%d.%d.%d.%d", &b[0], &b[1], &b[2], &b[3])
// 	if err != nil || n != 4 {
// 		return 0, fmt.Errorf("invalid IPv4: %q", ip)
// 	}
// 	return uint32(b[0]) |
// 			uint32(b[1])<<8 |
// 			uint32(b[2])<<16 |
// 			uint32(b[3])<<24,
// 		nil
// }

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
		byte(ip),
		byte(ip>>8),
		byte(ip>>16),
		byte(ip>>24),
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
	procGetIpAddrTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)

	buf := make([]byte, size)
	ret, _, _ := procGetIpAddrTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
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
	//rowPtr := unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + unsafe.Sizeof(num))

	//fmt.Printf("Interfaces:\n")
	fmt.Printf("Interfaces found: %d\n", num)
	// for i := uint32(0); i < num; i++ {
	// 	// row := *(*MIB_IFROW)(rowPtr)
	// 	// fmt.Printf("Index: %d, Type: %d, AdminStatus: %d, OperStatus: %d, MTU: %d\n",
	// 	// 	row.Index, row.Type, row.AdminStatus, row.OperStatus, row.Mtu)
	// 	// rowPtr = unsafe.Pointer(uintptr(rowPtr) + unsafe.Sizeof(row))
	// 	row := (*MIB_IFROW)(unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + offset))
	// 	fmt.Printf("[%d] Index: %d, MTU: %d, Type: %d, Status: %d\n",
	// 		i, row.Index, row.Mtu, row.Type, row.OperStatus)
	// 	offset += rowSize
	// }
	// for i := uint32(0); i < num; i++ {
	// 	// Use the package-level MIB_IFROW definition
	// 	row := (*MIB_IFROW)(unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + offset))

	// 	// Cleanly extract the description (it's a null-terminated byte array)
	// 	descr := ""
	// 	for j := 0; j < int(row.DescrLen) && j < len(row.Descr); j++ {
	// 		if row.Descr[j] == 0 {
	// 			break
	// 		}
	// 		descr += string(row.Descr[j])
	// 	}

	// 	fmt.Printf("[%d] Index: %d, Type: %d, MTU: %d, Name: %s\n",
	// 		i, row.Index, row.Type, row.Mtu, descr)
	// 	offset += rowSize
	// }
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
	ret, _, _ := procGetIpForwardTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	buf := make([]byte, size)
	ret, _, err := procGetIpForwardTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
	if ret != 0 {
		return false, 0, fmt.Errorf("GetIpForwardTable failed: %v", err)

	}

	// num := *(*uint32)(unsafe.Pointer(&buf[0]))
	// rowPtr := unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + unsafe.Sizeof(num))

	// for i := uint32(0); i < num; i++ {
	// 	row := *(*MIB_IPFORWARDROW)(rowPtr)
	// 	if row.ForwardDest == 0 && row.ForwardMask == 0 && row.ForwardIfIndex == ifIndex {
	// 		return true, row.ForwardNextHop, nil
	// 	}
	// 	rowPtr = unsafe.Pointer(uintptr(rowPtr) + unsafe.Sizeof(row))
	// }
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

var (
	kernel32                    = windows.NewLazySystemDLL("kernel32.dll")
	procSetConsoleTextAttribute = kernel32.NewProc("SetConsoleTextAttribute")
	procGetStdHandle            = kernel32.NewProc("GetStdHandle")
)

const (
	STD_OUTPUT_HANDLE    = uint32(-11 & 0xFFFFFFFF) // cast to uint32
	FOREGROUND_RED       = 0x0004
	FOREGROUND_GREEN     = 0x0002
	FOREGROUND_BLUE      = 0x0001
	FOREGROUND_INTENSITY = 0x0008

	// derived colors
	FOREGROUND_YELLOW        = FOREGROUND_RED | FOREGROUND_GREEN
	FOREGROUND_BRIGHT_YELLOW = FOREGROUND_YELLOW | FOREGROUND_INTENSITY

	FOREGROUND_MAGENTA        = FOREGROUND_RED | FOREGROUND_BLUE
	FOREGROUND_BRIGHT_MAGENTA = FOREGROUND_MAGENTA | FOREGROUND_INTENSITY
)

func colorPrintf(color uintptr, msg string, a ...any) {
	//fmt.Printf("\x1b[31m"+msg+"\x1b[0m\n", a...) // XXX: this doesn't work in admin cmd.exe, it's shown raw.
	hStdout := windows.Stdout
	// h2, _, callErr := procGetStdHandle.Call(uintptr(STD_OUTPUT_HANDLE))
	// handle := windows.Handle(h2)
	// if handle == 0 || handle == windows.InvalidHandle {
	// 	// callErr is only meaningful on failure
	// 	if callErr != nil && callErr != windows.ERROR_SUCCESS {
	// 		panic(fmt.Errorf("GetStdHandle failed: %w", callErr))
	// 	}
	// 	panic(fmt.Errorf("GetStdHandle returned invalid handle"))
	// }
	// if hStdout != handle {
	// 	panic(fmt.Errorf("unexpected diff. handles for stdout: %d,%d\n", hStdout, handle))
	// }
	var csbi windows.ConsoleScreenBufferInfo
	windows.GetConsoleScreenBufferInfo(hStdout, &csbi)
	origAttr := csbi.Attributes

	h2 := uintptr(hStdout)
	//set red
	procSetConsoleTextAttribute.Call(h2, color)
	fmt.Printf(msg, a...)
	//restore
	procSetConsoleTextAttribute.Call(h2, uintptr(origAttr))
}

func greenPrintf(msg string, a ...any) {
	colorPrintf(FOREGROUND_GREEN|FOREGROUND_INTENSITY, msg, a...)
}

func redPrintf(msg string, a ...any) {
	colorPrintf(FOREGROUND_RED|FOREGROUND_INTENSITY, msg, a...)
}

func cautionPrintf(msg string, a ...any) {
	colorPrintf(FOREGROUND_BRIGHT_MAGENTA, msg, a...)
}

// indicates the resulting state was already present, eg. deleting a gw, was already deleted by something else
// but could be an error if this wasn't expected.
func yellowPrintf(msg string, a ...any) {
	colorPrintf(FOREGROUND_BRIGHT_YELLOW, msg, a...)
}

// // Map common IP Helper error codes to human-readable text
// func ipHelperErrText(code uintptr /*uint32*/) string {
// 	switch code {
// 	case 0:
// 		return "SUCCESS"
// 	case 87: // ERROR_INVALID_PARAMETER
// 		return "One or more arguments are not correct"
// 	case 160: // ERROR_NOACCESS
// 		return "Attempt to access the address in memory that is not valid(dev/coding error)"
// 	default:
// 		return fmt.Sprintf("Unknown IP Helper error code: %d, but errno says: '%v'", code, windows.Errno(code))
// 	}
// }

// func forceSetDefaultGateway(gw uint32, ifIndex uint32) error {
// 	//according to Microsoft's IP Helper API documentation, unused routing metrics MUST be set to -1 (which is 0xFFFFFFFF or ^uint32(0)).
// 	// When you pass 0 to these metrics, CreateIpForwardEntry rejects the entire struct because 0 is an invalid metric value,
// 	// hence "One or more arguments are not correct" (Error 160).
// 	// 1. Prepare the row
// 	row := MIB_IPFORWARDROW{
// 		ForwardDest:    0,
// 		ForwardMask:    0,
// 		ForwardNextHop: gw,
// 		ForwardIfIndex: ifIndex,
// 		ForwardType:    4, // MIB_IPROUTE_TYPE_INDIRECT
// 		ForwardProto:   3, // MIB_IPPROTO_NETMGMT
// 		ForwardMetric1: 1,
// 		ForwardMetric2: ^uint32(0), // CRITICAL: Unused metrics must be -1
// 		ForwardMetric3: ^uint32(0),
// 		ForwardMetric4: ^uint32(0),
// 		ForwardMetric5: ^uint32(0),
// 	}

// 	// 2. Always attempt to delete first to clear the path
// 	// We ignore the return because if it doesn't exist, that's fine.
// 	_, _, _ = procDeleteIpForwardEntry.Call(uintptr(unsafe.Pointer(&row)))
// 	_ = deleteDefaultGateway(gw, ifIndex)

// 	// 3. Create the new entry
// 	ret, _, _ := procCreateIpForwardEntry.Call(uintptr(unsafe.Pointer(&row)))
// 	if ret != 0 {
// 		//return fmt.Errorf("CreateIpForwardEntry failed: %d %w", ret, windows.Errno(ret))
// 		return fmt.Errorf("CreateIpForwardEntry failed: %w (code %d)", windows.Errno(ret), ret)
// 	}
// 	return nil
// }

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
	procGetIpForwardTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	buf := make([]byte, size)
	ret, _, _ := procGetIpForwardTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)

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
				procDeleteIpForwardEntry.Call(uintptr(unsafe.Pointer(row)))
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
	ret, _, _ = procCreateIpForwardEntry.Call(uintptr(unsafe.Pointer(&row)))
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
	ret, _, _ = procCreateIpForwardEntry.Call(uintptr(unsafe.Pointer(&newRow)))
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
	ret, _, err := procDeleteIpForwardEntry.Call(uintptr(unsafe.Pointer(&row)))
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

	ret, _, _ := procDeleteIpForwardEntry.Call(uintptr(unsafe.Pointer(&row)))

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
		return 0, fmt.Errorf("Failed to convert common IP %s into uint32", commonIP)
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

// // expects big endian
// func ipv4StringBE(ip uint32) string {
// 	var buf [15]byte
// 	n := formatIPv4(buf[:], ip)
// 	return string(buf[:n])
// }

// func findPhysicalInterface() (uint32, error) {
// 	size := uint32(15000)
// 	for {
// 		b := make([]byte, size)
// 		err := windows.GetAdaptersAddresses(windows.AF_INET, windows.GAA_FLAG_SKIP_ANYCAST, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])), &size)
// 		if err == nil {
// 			addr := (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0]))
// 			for addr != nil {
// 				// Filter for: Physical (Ethernet/WiFi) + OperStatus Up
// 				// 6 = Ethernet, 71 = WiFi
// 				if (addr.IfType == 6 || addr.IfType == 71) && addr.OperStatus == windows.IfOperStatusUp {
// 					// Ensure it has at least one Unicast address (an IP)
// 					if addr.FirstUnicastAddress != nil {
// 						fmt.Printf("Found candidate interface: %s (Index: %d)\n", windows.BytePtrToString(addr.Description), addr.IfIndex)
// 						return addr.IfIndex, nil
// 					}
// 				}
// 				addr = addr.Next
// 			}
// 			return 0, fmt.Errorf("no active physical interface found")
// 		}
// 		if err != windows.ERROR_BUFFER_OVERFLOW {
// 			return 0, err
// 		}
// 	}
// }

// func getIndexFromGUID(savedGUID string) (uint32, error) {
// 	size := uint32(15000)
// 	b := make([]byte, size)
// 	err := windows.GetAdaptersAddresses(windows.AF_INET, 0, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])), &size)
// 	if err != nil {
// 		return 0, err
// 	}

// 	addr := (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0]))
// 	for addr != nil {
// 		if windows.BytePtrToString(addr.AdapterName) == savedGUID {
// 			return addr.IfIndex, nil
// 		}
// 		addr = addr.Next
// 	}
// 	return 0, fmt.Errorf("interface not found")
// }

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
		return "", fmt.Errorf("Error opening file '%s', err:'%w' Create the file and store an IP like 192.168.1.1 on a line. # are comments (inline too)\n", gwFile, err)
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
		return "", fmt.Errorf("Error: No gateway IP found in gateway.cfg")
	case 1:
		gatewayIP := foundIPs[0]
		return gatewayIP, nil
	default:
		// // 4. Handle multiple IPs found
		// fmt.Printf("Error: Multiple IP entries found in gateway.cfg:\n")
		// for _, ip := range foundIPs {
		// 	fmt.Printf("  - %s\n", ip)
		// }
		// fmt.Println("Please ensure only one IP is active (comment out the rest).")
		//if len(foundIPs) > 1 {
		return "", fmt.Errorf("multiple IP entries found: [%s]. Please ensure only one is active",
			strings.Join(foundIPs, ", "))
		//}
	}
}

func main() {
	defer func() {
		fmt.Printf("Press Enter to exit ")
		var dummy string
		_, _ = fmt.Scanln(&dummy)
	}()

	if err := listIfIndexes(); err != nil {
		fmt.Println("Error listing interfaces:", err)
	} else {
		listInterfaceIPs()
	}

	ifIndex, _, err := getTargetInterface() //getDefaultIfIndex()
	if err != nil {
		fmt.Println("Cannot get default interface:", err)
		return
	}

	fmt.Printf("default interface index: %d\n", ifIndex)

	exists, existingGW, err := hasDefaultGateway(ifIndex)
	if err != nil {
		fmt.Println(err)
		return
	}

	if exists {
		// redPrintf("Warning: default gateway already exists on this interface: %d.%d.%d.%d\n",
		// 	byte(existingGW), byte(existingGW>>8), byte(existingGW>>16), byte(existingGW>>24))
		// Fixed printing for BigEndian
		// ip := *(*[4]byte)(unsafe.Pointer(&existingGW))
		// var buf [15]byte
		// n := formatIPv4(buf[:], existingGW)
		// ip := string(buf[:n])
		//fmt.Printf("Current gateway on interface: %d.%d.%d.%d\n",
		// redPrintf("Warning: default gateway already exists on this interface: %d.%d.%d.%d\n",
		// 	ip[0], ip[1], ip[2], ip[3])

		//normalized := bits.ReverseBytes32(existingGW)
		fmt.Printf("raw:        0x%08X\n", existingGW)
		//fmt.Printf("normalized: 0x%08X\n", normalized)
		//redPrintf("Warning: default gateway already exists on this interface: %s", ipv4String(existingGW))//wrong order
		//fmt.Println(ipv4String(normalized))
		//redPrintf("Warning: default gateway already exists on this interface: %s", ipv4StringBE(normalized))
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

	defer func() {
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
		} else {
			redPrintf("Not removing on-link gateway (wasn't set? run: route print -4)")
		}
	}()

	defer func() {
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
		} else {
			redPrintf("Not removing gateway (wasn't set? run: route print -4)")
		}
	}()

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

	if err := clearPersistentGatewayForIndex(ifIndex); err != nil {
		fmt.Println("Failed to delete persistent gateway(ie. the one set in LAN adapter settings, seen by 'route print' under 'Persistent Routes'), err:", err)
		return //FIXME: exit codes!
	}
	// Set proper gateway
	if err := forceSetDefaultGateway(targetGW, ifIndex); err != nil {
		redPrintf("Failed to set gateway: %v\n", err)
		return
	}

	// 3. THE WAITING ROOM
	cautionPrintf("\n>>> Gateway is ACTIVE. Internet is routed.\n")
	cautionPrintf(">>> Press Ctrl+C to disconnect and cleanup.\n")
	//fmt.Println("Default gateway set. Press Ctrl+C to exit and remove it.")

	// Catch Ctrl+C to remove gateway on exit
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	fmt.Println("\n[!] Shutdown signal received. Cleaning up routes...")
	// The defers will now trigger as main() finishes after this point.
}
