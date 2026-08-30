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
	"io"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/workturnedplay/wincoe"
)

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
	defer func() {
		if closeErr := k.Close(); closeErr != nil {
			redPrintf("Warning: failed to close registry key %s: %v\n", path, closeErr)
		}
	}()

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

// fetchIphlpapiTable implements the standard two-call "query required size,
// then fetch" pattern shared by GetIpForwardTable/GetIfTable/GetIpAddrTable.
//
// It guards against ever indexing an empty buffer (buf[0] on a zero-length
// slice would panic) by treating a required size of 0 as "no entries" and
// returning (nil, nil) instead of allocating and dereferencing an empty
// slice.
//
// The underlying table can grow between the size query and the fetch (e.g.
// a route or interface appearing concurrently), in which case the fetch
// call itself reports ERROR_INSUFFICIENT_BUFFER with an updated size; this
// is retried a bounded number of times before giving up.
//
// query must tolerate being called with a nil pointer for the size-probing
// call (i.e. pass nil for pv and read back *size), as all of Iphlpapi's
// classic table-getters do.
func fetchIphlpapiTable(what string, query func(pv unsafe.Pointer, size *uint32) wincoe.WinResult) ([]byte, error) {
	const maxAttempts = 5

	var size uint32
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		res := query(nil, &size)
		if res.Failed() && !res.ErrIs(windows.ERROR_INSUFFICIENT_BUFFER) {
			return nil, fmt.Errorf("%s size query failed: %w", what, res.Err)
		}
		if size == 0 {
			// A genuinely empty table (or, defensively, an
			// ERROR_INSUFFICIENT_BUFFER response that nonetheless reported 0
			// bytes needed, which shouldn't happen per Windows' own contract
			// but would otherwise panic on &buf[0] below).
			return nil, nil
		}

		buf := make([]byte, size)
		res = query(unsafe.Pointer(&buf[0]), &size)
		if res.Succeeded() {
			if len(buf) < 4 {
				return nil, fmt.Errorf("%s returned a buffer too small to contain even the entry count (%d byte(s))", what, len(buf))
			}
			return buf, nil
		}
		if !res.ErrIs(windows.ERROR_INSUFFICIENT_BUFFER) {
			return nil, fmt.Errorf("%s failed: %w", what, res.Err)
		}
		// Table grew between the size query and the fetch; loop back and
		// requery with the updated 'size' the fetch call itself reported.
	}
	return nil, fmt.Errorf("%s: table size kept changing across %d attempts, giving up", what, maxAttempts)
}

func listInterfaceIPs() error {
	buf, err := fetchIphlpapiTable("GetIpAddrTable", func(pv unsafe.Pointer, size *uint32) wincoe.WinResult {
		return wincoe.GetIpAddrTable(pv, size, false)
	})
	if err != nil {
		return err
	}

	var num uint32
	if buf != nil {
		num = *(*uint32)(unsafe.Pointer(&buf[0]))
	}
	fmt.Printf("\n--- IP Address Table (%d entries) ---\n", num)

	// Each row is 24 bytes (5*4 + 2*2)
	rowSize := uintptr(24)
	offset := uintptr(4)

	for i := uint32(0); i < num; i++ {
		row := (*wincoe.MIB_IPADDRROW)(unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + offset))

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
	buf, err := fetchIphlpapiTable("GetIfTable", func(pv unsafe.Pointer, size *uint32) wincoe.WinResult {
		return wincoe.GetIfTable(pv, size, false)
	})
	if err != nil {
		return err
	}
	if buf == nil {
		fmt.Println("Interfaces found: 0")
		return nil
	}

	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	// x64 FIX: On 64-bit Windows, there are 4 bytes of padding after 'num'
	// to align the first MIB_IFROW to 8 bytes.
	// Offset is exactly 4 bytes (the size of 'num')
	offset := uintptr(4)
	rowSize := unsafe.Sizeof(wincoe.MIB_IFROW{})

	fmt.Printf("Interfaces found: %d\n", num)

	for i := uint32(0); i < num; i++ {
		row := (*wincoe.MIB_IFROW)(unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + offset))

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
	buf, err := fetchIphlpapiTable("GetIpForwardTable", func(pv unsafe.Pointer, size *uint32) wincoe.WinResult {
		return wincoe.GetIpForwardTable(pv, size, false)
	})
	if err != nil {
		return false, 0, err
	}
	if buf == nil {
		return false, 0, nil
	}

	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	// MIB_IPFORWARDTABLE also has the 4-byte padding on x64
	offset := uintptr(4) // Reverted to 4 bytes
	rowSize := unsafe.Sizeof(wincoe.MIB_IPFORWARDROW{})

	for i := uint32(0); i < num; i++ {
		row := (*wincoe.MIB_IPFORWARDROW)(unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + offset))
		if row.ForwardDest == 0 && row.ForwardMask == 0 && row.ForwardIfIndex == ifIndex {
			return true, row.ForwardNextHop, nil
		}
		offset += rowSize
	}
	return false, 0, nil
}

func colorPrintf(color uint16, msg string, a ...any) {
	hStdout := windows.Stdout
	var csbi windows.ConsoleScreenBufferInfo
	if err := windows.GetConsoleScreenBufferInfo(hStdout, &csbi); err != nil {
		panic(fmt.Errorf("GetConsoleScreenBufferInfo failed: %w", err))
	}
	origAttr := csbi.Attributes

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

func forceSetDefaultGateway(targetGW, ifIndex uint32) error {
	buf, err := fetchIphlpapiTable("GetIpForwardTable", func(pv unsafe.Pointer, size *uint32) wincoe.WinResult {
		return wincoe.GetIpForwardTable(pv, size, false)
	})
	if err != nil {
		// Best-effort: not knowing the existing routing table just means we
		// fall back to "no existing route/metric found" below, same as the
		// buf==nil (empty table) case.
		redPrintf("Warning: %v; proceeding without checking for a pre-existing default route\n", err)
	}

	var existingRow *wincoe.MIB_IPFORWARDROW
	var ifMetric uint32

	if buf != nil {
		num := *(*uint32)(unsafe.Pointer(&buf[0]))
		offset := uintptr(4)
		rowSize := unsafe.Sizeof(wincoe.MIB_IPFORWARDROW{})

		for i := uint32(0); i < num; i++ {
			row := (*wincoe.MIB_IPFORWARDROW)(unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + offset))

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
				if delRes := wincoe.DeleteIpForwardEntry(unsafe.Pointer(row)); delRes.Failed() {
					redPrintf("Warning: failed to delete pre-existing default-route entry on interface %d: %v\n", ifIndex, delRes.Err)
				}
			}
			offset += rowSize
		}
	}

	// FINAL FALLBACK: If we found no routes at all for this interface, use 25
	if ifMetric == 0 || ifMetric == ^uint32(0) {
		ifMetric = 281
		redPrintf("Couldn't find the metric automatically, using metric %d instead.", ifMetric)
	}

	var newRow wincoe.MIB_IPFORWARDROW

	if existingRow != nil {
		// 2a. Safest approach: Clone the OS parameters and just swap the IP
		newRow = *existingRow
		newRow.ForwardNextHop = targetGW
		newRow.ForwardAge = 0
	} else {
		// 2b. Fallback if no gateway existed at all
		newRow = wincoe.MIB_IPFORWARDROW{
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
	}

	// Add a specific route to the GATEWAY ITSELF first, telling Windows it's "On-Link"
	// Route: [TargetGW] Mask 255.255.255.255 -> Interface Index (No Gateway)
	row := wincoe.MIB_IPFORWARDROW{
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
	res := wincoe.CreateIpForwardEntry(unsafe.Pointer(&row))
	if res.Failed() {
		//continue because it works w/o this anyway!
		if res.ErrIs(windows.Errno(5010)) {
			// if The object already exists. (code 5010)
			yellowPrintf("The entry for on-link gw already existed, err: %v", res.Err)
		} else {
			// if not: The object already exists. (code 5010)
			//then nothing to remove as it failed to add it
			removeDirectGWRoute = false
			redPrintf("CreateIpForwardEntry for gw being on-link failed: %v\n", res.Err)
		}
	}

	// 3. Create the route
	removeActiveGateway = true // rather fail to delete it than miss deleting it due to race.
	res = wincoe.CreateIpForwardEntry(unsafe.Pointer(&newRow))
	if res.Failed() {
		if res.ErrIs(windows.Errno(5010)) {
			// The object already exists. (code 5010)
			redPrintf("Unexpectedly gw already exists(but shoulda been deleted before by our code): %v\n", res.Err)
		} else {
			removeActiveGateway = false
		}
		return fmt.Errorf("CreateIpForwardEntry failed: %w", res.Err)
	}

	return nil
}

var removeActiveGateway, removeDirectGWRoute bool = false, false

// Delete default gateway
func deleteDefaultGateway(gw, ifIndex uint32) error {
	/*
	   The reason deleteDefaultGateway worked with Metric1: 1 even if you created it with 281 is because DeleteIpForwardEntry
	   is actually quite "fuzzy." It primarily looks for a match on Destination, Mask, NextHop, and IfIndex. As long as those match,
	   it usually ignores the metric during deletion unless you have multiple identical routes with different metrics.
	*/
	row := wincoe.MIB_IPFORWARDROW{
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
	res := wincoe.DeleteIpForwardEntry(unsafe.Pointer(&row))
	if res.Failed() {
		return fmt.Errorf("DeleteIpForwardEntry failed, err(wrong):'%v', errno(correct):'%w'", res.CallStatus, res.Err) //nolint:errorlint // wrap only the real error!
	}
	return nil
}

func deleteDirectRoute(targetGW, ifIndex uint32) error {
	row := wincoe.MIB_IPFORWARDROW{
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

	res := wincoe.DeleteIpForwardEntry(unsafe.Pointer(&row))
	if res.Failed() {
		// 1168 is ERROR_NOT_FOUND. If it's already gone, we don't care.
		return fmt.Errorf("DeleteDirectRoute failed: (%w)", res.Err)
	}
	return nil
}

// Get the best interface index for default route
func getDefaultIfIndex() (uint32, error) {
	var ifIndex uint32
	// Use a common IP to find the best local interface
	const commonIP = "1.1.1.1"
	common, err := ipv4ToUint32LE(commonIP)
	if err != nil {
		//FIXME: DRY the message
		redPrintf("Failed to convert common IP %s into uint32\n", commonIP)
		return 0, fmt.Errorf("failed to convert common IP %s into uint32", commonIP)
	}

	res := wincoe.GetBestInterface(common, &ifIndex)
	if res.Failed() {
		return 0, fmt.Errorf("GetBestInterface failed: %v %w", res.CallStatus, res.Err) // nolint:errorlint //we only want the real error to get wrapped
	}
	return ifIndex, nil
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
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			return nil, fmt.Errorf("GetAdaptersAddresses failed: %w", err)
		}
	}
}

func getTargetInterface() (uint32, string, error) {
	// 1. Try the "Easy Way" (works if a gateway exists)
	idx, err := getDefaultIfIndex()
	if err == nil {
		// We still need the GUID for registry cleaning; a lookup failure here
		// is non-fatal (the interface index itself is still perfectly usable),
		// so just warn instead of aborting interface selection over it.
		guid, guidErr := getInterfaceGUID(idx)
		if guidErr != nil {
			redPrintf("Warning: failed to resolve interface GUID for index %d (registry cleanup may be incomplete): %v\n", idx, guidErr)
		}
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
	input, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return NetworkAdapter{}, fmt.Errorf("failed to read adapter selection: %w", err)
	}
	input = strings.TrimSpace(input)
	if input == "" {
		return NetworkAdapter{}, errors.New("no adapter selection entered")
	}

	choice, err := strconv.Atoi(input)
	if err != nil {
		return NetworkAdapter{}, fmt.Errorf("invalid adapter selection %q: %w", input, err)
	}

	if choice < 1 || choice > len(adapters) {
		return NetworkAdapter{}, fmt.Errorf("invalid selection %d (must be between 1 and %d)", choice, len(adapters))
	}

	return adapters[choice-1], nil
}

const gwFile = "gateway.cfg"

func getWantedGW() (string, error) {
	file, err := os.Open(gwFile)
	if err != nil {
		return "", fmt.Errorf("failed opening file '%s', err:'%w' Create the file and store an IP like 192.168.1.1 on a line. # are comments (inline too)", gwFile, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			redPrintf("Warning: failed to close %q: %v\n", gwFile, closeErr)
		}
	}()

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
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("failed reading %q: %w", gwFile, err)
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

// getTargetInterfaceWithRetry calls getTargetInterface in a loop, letting the
// user fix a transient problem (e.g. plug the network cable back in) and
// retry with a single keypress, instead of having to relaunch the whole
// program — and get re-prompted by UAC for elevation — just to try again.
//
// Returns the first successful result, or the last error if stdin isn't an
// interactive console (in which case waiting for a keypress could never be
// satisfied, so looping forever would just hang the process).
func getTargetInterfaceWithRetry() (uint32, error) {
	for {
		ifIndex, _, err := getTargetInterface()
		if err == nil {
			return ifIndex, nil
		}

		if !wincoe.IsStdinConsoleInteractive() {
			return 0, err
		}

		redPrintf("Cannot get default interface: %v\n", err)
		cautionPrintf(">>> Fix the issue (e.g. plug the network cable back in), then press any key to retry, or Ctrl+C to exit...")
		waitAnyKeyRaw()
	}
}

// waitAnyKeyRaw blocks until a single key is pressed, reusing the same
// event-raw-mode plumbing as wincoe.WaitAnyKey (ClearStdin/WithConsoleEventRaw/
// ReadKeySequence) but without wincoe.WaitAnyKey's own hardcoded "Press any
// key to exit..." prompt, since callers here already printed their own,
// retry-specific prompt immediately beforehand.
func waitAnyKeyRaw() {
	var hadKey bool
	wincoe.WithConsoleEventRaw(func() {
		hadKey = wincoe.ClearStdin()
	})
	if hadKey {
		fmt.Print("(clrbuf)...")
	}

	done := make(chan struct{}, 1)
	go func() {
		wincoe.WithConsoleEventRaw(func() {
			wincoe.ReadKeySequence()
			if wincoe.ClearStdin() {
				fmt.Print("(clrbuf2).")
			}
		})
		done <- struct{}{}
	}()
	<-done
	fmt.Println()
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
	globalCleanup func() // Anchor to bridge inside main() to the callback safely
)

// The callback function that Windows calls during shutdown/logoff events.
// Since this utility operates entirely out of the Windows Command Prompt or PowerShell, utilizing SetConsoleCtrlHandler is significantly cleaner.
// It registers a control handler function that directly catches CTRL_SHUTDOWN_EVENT and CTRL_LOGOFF_EVENT sent by Win11 during a restart.
func consoleCtrlHandler(ctrlType uint32) uintptr {
	switch ctrlType {
	case wincoe.CTRL_C_EVENT, wincoe.CTRL_BREAK_EVENT, wincoe.CTRL_CLOSE_EVENT, wincoe.CTRL_LOGOFF_EVENT, wincoe.CTRL_SHUTDOWN_EVENT:
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

	ifIndex, err := getTargetInterfaceWithRetry()
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
	if err != nil {
		redPrintf("Failed to convert wanted gw IP %s into uint32\n", wantedGW)
		return
	}

	fmt.Printf("The gateway that we want is %s aka 0x%08X\n",
		ipv4StringLE(targetGW), targetGW)

	token := windows.GetCurrentProcessToken()
	var isAdmin bool = token.IsElevated()
	if !isAdmin {
		redPrintf("Must run as admin to effect changes!\n")
		return
	}

	// 1. Put Stdin into raw mode so we can capture Ctrl+R instantly (without hitting Enter)
	// We keep ENABLE_PROCESSED_INPUT active so Ctrl+C still sends SIGINT to our channel.
	var oldMode uint32
	if err := windows.GetConsoleMode(windows.Stdin, &oldMode); err != nil {
		redPrintf("Warning: GetConsoleMode failed, Ctrl+R raw-mode toggling won't work: %v\n", err)
	} else {
		newMode := oldMode &^ (windows.ENABLE_LINE_INPUT | windows.ENABLE_ECHO_INPUT | windows.ENABLE_PROCESSED_INPUT)
		if err := windows.SetConsoleMode(windows.Stdin, newMode); err != nil {
			redPrintf("Warning: SetConsoleMode(raw) failed, Ctrl+R raw-mode toggling won't work: %v\n", err)
		} else {
			// Executes 2nd on exit, restoring cooked console
			defer func() {
				if err := windows.SetConsoleMode(windows.Stdin, oldMode); err != nil {
					redPrintf("Warning: failed to restore original console mode on exit: %v\n", err)
				}
			}()
		}
	}

	var isActive bool

	// 2. Wrap routing logic into an activate closure
	activate := func() {
		if err := clearPersistentGatewayForIndex(ifIndex); err != nil {
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
	defer deactivate()

	// Bind the local closure to the global function holder
	// Bind our local cleanup logic to the package-level anchor
	globalCleanup = deactivate

	// Register the callback with Windows via kernel32.dll using wincoe's bound wrapper
	res := wincoe.RegisterCtrlHandler(consoleCtrlHandler)
	if res.Failed() {
		redPrintf("CRITICAL: Failed to register console control handler: %v\n", res.Err)
		return
	} else {
		// Just a quiet sanity check confirmation during startup
		fmt.Println("OS termination handler successfully registered.")
	}

	// Initial Activation
	activate()

	// 4. THE WAITING ROOM
	cautionPrintf(">>> Press Ctrl+R to toggle state. Press Ctrl+C to disconnect and exit.\n")

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
}
