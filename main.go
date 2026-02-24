package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
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

// // MIB_IPFORWARDROW struct for SetIpForwardEntry
// type MIB_IPFORWARDROW struct {
// 	DwForwardDest      uint32
// 	DwForwardMask      uint32
// 	DwForwardPolicy    uint32
// 	DwForwardNextHop   uint32
// 	DwForwardIfIndex   uint32
// 	DwForwardType      uint32
// 	DwForwardProto     uint32
// 	DwForwardAge       uint32
// 	DwForwardNextHopAS uint32
// 	DwForwardMetric1   uint32
// 	DwForwardMetric2   uint32
// 	DwForwardMetric3   uint32
// 	DwForwardMetric4   uint32
// 	DwForwardMetric5   uint32
// }

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

// Convert IPv4 string to uint32 in a way that produces Network Byte Order in memory
func ipv4ToUint32(ip string) uint32 {
	var b [4]byte
	fmt.Sscanf(ip, "%d.%d.%d.%d", &b[0], &b[1], &b[2], &b[3])
	// Use LittleEndian so that b[0] (192) ends up at the lowest memory address
	return binary.LittleEndian.Uint32(b[:])
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
)

func redPrintf(msg string, a ...interface{}) {
	//fmt.Printf("\x1b[31m"+msg+"\x1b[0m\n", a...) // XXX: this doesn't work in admin cmd.exe, it's shown raw.
	h := windows.Stdout
	// get stdout handle
	h2, _, _ := procGetStdHandle.Call(uintptr(STD_OUTPUT_HANDLE))
	if uintptr(h) != h2 {
		panic(fmt.Sprintf("unexpected diff. handles for stdout: %d,%d\n", h, h2))
	}
	var csbi windows.ConsoleScreenBufferInfo
	windows.GetConsoleScreenBufferInfo(h, &csbi)
	origAttr := csbi.Attributes

	//set red
	procSetConsoleTextAttribute.Call(h2, FOREGROUND_RED|FOREGROUND_INTENSITY)
	fmt.Printf(msg+"\n", a...)
	//restore
	procSetConsoleTextAttribute.Call(h2, uintptr(origAttr))
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

func forceSetDefaultGateway(targetGW uint32, ifIndex uint32) error {
	var size uint32
	procGetIpForwardTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	buf := make([]byte, size)
	ret, _, _ := procGetIpForwardTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)

	var existingRow *MIB_IPFORWARDROW

	if ret == 0 {
		num := *(*uint32)(unsafe.Pointer(&buf[0]))
		offset := uintptr(4)
		rowSize := unsafe.Sizeof(MIB_IPFORWARDROW{})

		for i := uint32(0); i < num; i++ {
			row := (*MIB_IPFORWARDROW)(unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + offset))

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

	var newRow MIB_IPFORWARDROW

	if existingRow != nil {
		// 2a. Safest approach: Clone the OS parameters and just swap the IP
		newRow = *existingRow
		newRow.ForwardNextHop = targetGW
		newRow.ForwardAge = 0
	} else {
		// 2b. Fallback if no gateway existed at all
		newRow = MIB_IPFORWARDROW{
			ForwardDest:    0,
			ForwardMask:    0,
			ForwardNextHop: targetGW,
			ForwardIfIndex: ifIndex,
			ForwardType:    4, // MIB_IPROUTE_TYPE_INDIRECT
			ForwardProto:   3, // MIB_IPPROTO_NETMGMT
			ForwardMetric1: 1,
			ForwardMetric2: ^uint32(0), // -1
			ForwardMetric3: ^uint32(0), // -1
			ForwardMetric4: ^uint32(0), // -1
			ForwardMetric5: ^uint32(0), // -1
		}
	}

	// 3. Create the route
	ret, _, _ = procCreateIpForwardEntry.Call(uintptr(unsafe.Pointer(&newRow)))
	if ret != 0 {
		return fmt.Errorf("CreateIpForwardEntry failed: %w (code %d)", windows.Errno(ret), ret)
	}
	return nil
}

// Delete default gateway
func deleteDefaultGateway(gw uint32, ifIndex uint32) error {
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

// Get the best interface index for default route
func getDefaultIfIndex() (uint32, error) {
	var ifIndex uint32
	// Use a common IP to find the best local interface
	ret, _, err := procGetBestInterface.Call(uintptr(ipv4ToUint32("8.8.8.8")), uintptr(unsafe.Pointer(&ifIndex)))
	if ret != 0 {
		return 0, fmt.Errorf("GetBestInterface failed: %d %v %w", ret, err, windows.Errno(ret)) //FIXME
	}
	return ifIndex, nil
}

func main() {
	defer func() {
		fmt.Printf("Press Enter to exit")
		var dummy string
		_, _ = fmt.Scanln(&dummy)
	}()

	if err := listIfIndexes(); err != nil {
		fmt.Println("Error listing interfaces:", err)
	} else {
		listInterfaceIPs()
	}

	ifIndex, err := getDefaultIfIndex()
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
		ip := *(*[4]byte)(unsafe.Pointer(&existingGW))
		//fmt.Printf("Current gateway on interface: %d.%d.%d.%d\n",
		redPrintf("Warning: default gateway already exists on this interface: %d.%d.%d.%d\n",
			ip[0], ip[1], ip[2], ip[3])
	}

	token := windows.GetCurrentProcessToken()
	//defer token.Close() // Add this, bad 'gemini 3 thinking' lol
	var isAdmin bool = token.IsElevated()
	if !isAdmin {
		redPrintf("Must run as admin to effect changes!")
		return
	}
	//fmt.Println("Running elevated?", isAdmin)

	// Example gateway, replace with the “real” GW you want
	//gw := ipv4ToUint32("192.168.1.1")
	targetGW := ipv4ToUint32("192.168.1.1")
	ip := *(*[4]byte)(unsafe.Pointer(&targetGW))
	fmt.Printf("Gateway to set (uint32): %08X aka %d.%d.%d.%d\n",
		targetGW, ip[0], ip[1], ip[2], ip[3])

	if err := clearPersistentGatewayForIndex(ifIndex); err != nil {
		fmt.Println("Failed to delete persistent gateway(ie. the one set in LAN adapter settings, seen by 'route print' under 'Persistent Routes'), err:", err)
		return //FIXME: exit codes!
	}
	// Set proper gateway
	if err := forceSetDefaultGateway(targetGW, ifIndex); err != nil {
		fmt.Println("Failed to set gateway:", err)
		return
	}
	fmt.Println("Default gateway set. Press Ctrl+C to exit and remove it.")

	// Catch Ctrl+C to remove gateway on exit
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	if err := deleteDefaultGateway(targetGW, ifIndex); err != nil {
		fmt.Println("Failed to delete gateway:", err)
	} else {
		fmt.Println("Default gateway removed, network disabled.")
	}
}
