//go:build windows && amd64

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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/workturnedplay/wincoe"
)

const (
	errnoObjectAlreadyExists = windows.Errno(5010) // ERROR_OBJECT_ALREADY_EXISTS
	errnoNotFound            = windows.Errno(1168) // ERROR_NOT_FOUND
)

// forEachAdapter calls visit for every adapter GetAdaptersAddresses reports (IPv4 family), until visit returns true.
// It owns the grow-and-retry-on-ERROR_BUFFER_OVERFLOW dance (bounded, unlike the two hand-rolled unbounded
// loops this replaces) and keeps the buffer alive for as long as the visited pointers are in use.
func forEachAdapter(flags uint32, visit func(a *windows.IpAdapterAddresses) (stop bool)) error {
	const maxAttempts = 5
	size := uint32(15000)
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if size == 0 {
			return errors.New("GetAdaptersAddresses: zero-sized buffer requested, can't continue")
		}
		b := make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_INET, flags, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])), &size)
		if err == nil {
			for addr := (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])); addr != nil; addr = addr.Next {
				if visit(addr) {
					break
				}
			}
			runtime.KeepAlive(b) // the visited pointers point INTO b, but are stored in noscan memory
			return nil
		}
		if errors.Is(err, windows.ERROR_NO_DATA) {
			return nil // no adapters at all
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			return fmt.Errorf("GetAdaptersAddresses failed: %w", err)
		}
		// 'size' now holds the required size; loop to retry with it.
	}
	return fmt.Errorf("GetAdaptersAddresses: required buffer size kept changing across %d attempts, giving up", maxAttempts)
}

func getInterfaceGUID(ifIndex uint32) (string, error) {
	var guid string
	found := false
	//0 = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST
	if err := forEachAdapter(0, func(a *windows.IpAdapterAddresses) bool {
		if a.IfIndex != ifIndex {
			return false
		}
		// Windows returns the GUID as the "AdapterName"
		guid = windows.BytePtrToString(a.AdapterName)
		found = true
		return true
	}); err != nil {
		return "", fmt.Errorf("getInterfaceGUID(index %d): %w", ifIndex, err)
	}
	if !found {
		return "", fmt.Errorf("GUID not found for index %d", ifIndex)
	}
	return guid, nil
}

// errDHCPEnabled is returned (wrapped) by checkInterfaceDHCPDisabled when the interface uses DHCP.
var errDHCPEnabled = errors.New("DHCP is enabled on the selected interface")

const persistentRoutesKeyPath = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PersistentRoutes`

func interfaceRegistryKeyPath(guid string) string {
	return `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\` + guid
}

func closeRegistryKey(k registry.Key, path string) {
	if closeErr := k.Close(); closeErr != nil {
		redPrintf("Warning: failed to close registry key %s: %v\n", path, closeErr)
	}
}

// checkInterfaceDHCPDisabled returns an error wrapping errDHCPEnabled if the interface (by GUID) has EnableDHCP != 0:
// the DHCP client would keep (re)installing its own default gateway behind our back, so this tool can't work right.
// A missing EnableDHCP value counts as static. Any other failure is returned as a plain wrapped error.
func checkInterfaceDHCPDisabled(guid string) error {
	path := interfaceRegistryKeyPath(guid)
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("failed to open registry key %s, err: %w", path, err)
	}
	defer closeRegistryKey(k, path)

	enabled, _, err := k.GetIntegerValue("EnableDHCP")
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("failed to read EnableDHCP from registry key %s, err: %w", path, err)
	}
	if enabled != 0 {
		return fmt.Errorf("%w: interface %s has EnableDHCP=%d, switch the adapter to a static IP first", errDHCPEnabled, guid, enabled)
	}
	return nil
}

// countLegacyPersistentRoutes returns how many values the legacy PersistentRoutes registry key holds (0 if the key is absent).
func countLegacyPersistentRoutes() (uint32, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, persistentRoutesKeyPath, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("failed to open registry key %s, err: %w", persistentRoutesKeyPath, err)
	}
	defer closeRegistryKey(k, persistentRoutesKeyPath)

	info, err := k.Stat()
	if err != nil {
		return 0, fmt.Errorf("failed to stat registry key %s, err: %w", persistentRoutesKeyPath, err)
	}
	return info.ValueCount, nil
}

func clearPersistentGatewayForIndex(ifIndex uint32) error {
	guid, err := getInterfaceGUID(ifIndex)
	if err != nil {
		return fmt.Errorf("failed to get GUID: %w", err)
	}

	path := interfaceRegistryKeyPath(guid)
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("failed to open registry key %s, err: %w", path, err)
	}
	defer closeRegistryKey(k, path)

	// Writing an empty slice to a MULTI_SZ effectively clears the list.
	// If Windows deletes the key entirely, that's actually fine—it means "No GW".
	err = k.SetStringsValue("DefaultGateway", []string{})
	if err != nil {
		return fmt.Errorf("failed to clear DefaultGateway for GUID interface '%s' with index '%d', err: %w", guid, ifIndex, err)
	}

	// Also clear the metric to prevent "ghost" metrics
	err = k.SetStringsValue("DefaultGatewayMetric", []string{})
	if err != nil {
		return fmt.Errorf("failed to clear DefaultGatewayMetric for GUID interface '%s' with index '%d', err: %w", guid, ifIndex, err)
	}

	fmt.Printf("Successfully scrubbed Registry for Interface %s with index %d\n", guid, ifIndex)
	return nil
}

// little endian like Windows
func ipv4ToUint32LE(ip string) (uint32, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return 0, fmt.Errorf("invalid IPv4 %q: %w", ip, err)
	}
	if !addr.Is4() {
		return 0, fmt.Errorf("invalid IPv4 %q: not an IPv4 address", ip)
	}
	b := addr.As4()
	return binary.LittleEndian.Uint32(b[:]), nil
}

// little endian like Windows
func ipv4StringLE(ip uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], ip)
	return netip.AddrFrom4(b).String()
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
		if res.Failed() && res.ErrIs(windows.ERROR_NO_DATA) {
			return nil, nil // Iphlpapi's way of saying "empty table"
		}
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
			return buf, nil
		}
		if res.ErrIs(windows.ERROR_NO_DATA) {
			return nil, nil
		}
		if !res.ErrIs(windows.ERROR_INSUFFICIENT_BUFFER) {
			return nil, fmt.Errorf("%s failed: %w", what, res.Err)
		}
		// Table grew between the size query and the fetch; loop back and
		// requery with the updated 'size' the fetch call itself reported.
	}
	return nil, fmt.Errorf("%s: table size kept changing across %d attempts, giving up", what, maxAttempts)
}

// fetchIphlpapiRows runs fetchIphlpapiTable and reinterprets the buffer (a DWORD entry count followed by that many
// rows of type T) as a []T that aliases the buffer, after verifying the claimed row count actually fits in it.
// Returns (nil, nil) for an empty table.
func fetchIphlpapiRows[T any](what string, query func(pv unsafe.Pointer, size *uint32) wincoe.WinResult) ([]T, error) {
	buf, err := fetchIphlpapiTable(what, query)
	if err != nil {
		return nil, fmt.Errorf("fetchIphlpapiRows(%s): %w", what, err)
	}
	if buf == nil {
		return nil, nil
	}
	if len(buf) < 4 {
		return nil, fmt.Errorf("%s returned a buffer too small to contain even the entry count (%d byte(s))", what, len(buf))
	}

	num := binary.LittleEndian.Uint32(buf[:4])
	if num == 0 {
		return nil, nil
	}

	var zero T
	rowSize := uint64(unsafe.Sizeof(zero))
	if uint64(num)*rowSize > uint64(len(buf)-4) {
		return nil, fmt.Errorf("%s claims %d row(s) of %d byte(s) each but only %d byte(s) follow the entry count", what, num, rowSize, len(buf)-4)
	}
	// All of these tables are DWORD-only structs (align 4) and start right after the 4-byte count; there is NO
	// extra x64 padding there (the old "x64 FIX" comments were wrong, offset 4 was always the correct one).
	return unsafe.Slice((*T)(unsafe.Pointer(&buf[4])), num), nil
}

func queryIPForwardTable(pv unsafe.Pointer, size *uint32) wincoe.WinResult {
	return wincoe.GetIpForwardTable(pv, size, false)
}

func isDefaultRouteOn(row *wincoe.MIB_IPFORWARDROW, ifIndex uint32) bool {
	return row.ForwardDest == 0 && row.ForwardMask == 0 && row.ForwardIfIndex == ifIndex
}

// ifRowDescription returns the (ANSI) description of row, up to its NUL terminator.
func ifRowDescription(row *wincoe.MIB_IFROW) string {
	d := row.Descr[:min(int(row.DescrLen), len(row.Descr))]
	if i := bytes.IndexByte(d, 0); i >= 0 {
		d = d[:i]
	}
	return string(d) // not byte-by-byte string(rune): that mangled non-ASCII descriptions
}

func listInterfaceIPs() error {
	rows, err := fetchIphlpapiRows[wincoe.MIB_IPADDRROW]("GetIpAddrTable", func(pv unsafe.Pointer, size *uint32) wincoe.WinResult {
		return wincoe.GetIpAddrTable(pv, size, false)
	})
	if err != nil {
		return fmt.Errorf("listInterfaceIPs: %w", err)
	}

	fmt.Printf("\n--- IP Address Table (%d entries) ---\n", len(rows))
	for i := range rows {
		row := &rows[i]
		fmt.Printf("IF Index %d: IP %s | Mask %s\n", row.Index, ipv4StringLE(row.Addr), ipv4StringLE(row.Mask))
	}
	fmt.Println("-------------------------------------")
	return nil
}

func listIfIndexes() error {
	rows, err := fetchIphlpapiRows[wincoe.MIB_IFROW]("GetIfTable", func(pv unsafe.Pointer, size *uint32) wincoe.WinResult {
		return wincoe.GetIfTable(pv, size, false)
	})
	if err != nil {
		return fmt.Errorf("listIfIndexes: %w", err)
	}

	fmt.Printf("Interfaces found: %d\n", len(rows))
	for i := range rows {
		row := &rows[i]
		fmt.Printf("[%d] Index: %d, MTU: %d, Name: %s\n", i, row.Index, row.Mtu, ifRowDescription(row))
	}
	return nil
}

// Enumerate routes and check if any default gateway exists on a given interface
func hasDefaultGateway(ifIndex uint32) (bool, uint32, error) {
	rows, err := fetchIphlpapiRows[wincoe.MIB_IPFORWARDROW]("GetIpForwardTable", queryIPForwardTable)
	if err != nil {
		return false, 0, fmt.Errorf("hasDefaultGateway: %w", err)
	}
	for i := range rows {
		if isDefaultRouteOn(&rows[i], ifIndex) {
			return true, rows[i].ForwardNextHop, nil
		}
	}
	return false, 0, nil
}

// consoleOutMu serializes colored console output: the console text attribute is process-global state and the
// console ctrl handler prints (via deactivate) from a different OS thread than main(), so two interleaved
// save/set/restore sequences could otherwise leave the console stuck in the wrong color.
var consoleOutMu sync.Mutex

func colorPrintf(color uint16, msg string, a ...any) {
	consoleOutMu.Lock()
	defer consoleOutMu.Unlock()

	printed := false
	err := wincoe.WithConsoleColor(windows.Stdout, color, func() {
		printed = true
		fmt.Printf(msg, a...)
	})
	if !printed {
		// stdout isn't a console (redirected / no console attached): color is impossible, so print plain
		// instead of panicking.
		fmt.Printf(msg, a...)
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: couldn't restore the console color: %v\n", err) //nolint:errcheck // best-effort
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
	rows, err := fetchIphlpapiRows[wincoe.MIB_IPFORWARDROW]("GetIpForwardTable", queryIPForwardTable)
	if err != nil {
		// Best-effort: not knowing the existing routing table just means we
		// fall back to "no existing route/metric found" below, same as the
		// empty table case.
		redPrintf("Warning: %v; proceeding without checking for a pre-existing default route\n", err)
	}

	var existingRow *wincoe.MIB_IPFORWARDROW
	var ifMetric uint32

	for i := range rows {
		row := &rows[i]

		// TRACK METRIC: If this row belongs to our interface, save its metric
		// as a candidate for our new route's metric.
		if ifMetric == 0 && row.ForwardIfIndex == ifIndex {
			ifMetric = row.ForwardMetric1
		}

		// If we find an active default gateway on our target interface...
		if isDefaultRouteOn(row, ifIndex) {
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
	}

	// FINAL FALLBACK: If we found no routes at all for this interface, use 281
	if ifMetric == 0 || ifMetric == ^uint32(0) {
		ifMetric = 281
		redPrintf("Couldn't find the metric automatically, using metric %d instead.\n", ifMetric)
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
		if res.ErrIs(errnoObjectAlreadyExists) {
			// if The object already exists. (code 5010)
			yellowPrintf("The entry for on-link gw already existed, err: %v\n", res.Err)
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
		if res.ErrIs(errnoObjectAlreadyExists) {
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
		return 0, fmt.Errorf("failed to convert common IP %s into uint32: %w", commonIP, err)
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
	err := forEachAdapter(windows.GAA_FLAG_SKIP_ANYCAST, func(a *windows.IpAdapterAddresses) bool {
		// 6 = Ethernet, 71 = WiFi, and status must be "Up"
		if (a.IfType != 6 && a.IfType != 71) || a.OperStatus != windows.IfOperStatusUp {
			return false
		}
		ipStr := "No IP"
		if a.FirstUnicastAddress != nil && a.FirstUnicastAddress.Address.Sockaddr != nil {
			// Extracting the IPv4 string for display
			sa := (*windows.RawSockaddrInet4)(unsafe.Pointer(a.FirstUnicastAddress.Address.Sockaddr))
			if sa.Family == windows.AF_INET {
				ipStr = netip.AddrFrom4(sa.Addr).String()
			}
		}
		adapters = append(adapters, NetworkAdapter{
			Index:       a.IfIndex,
			GUID:        windows.BytePtrToString(a.AdapterName),
			Description: windows.UTF16PtrToString(a.Description),
			IP:          ipStr,
		})
		return false
	})
	if err != nil {
		return nil, fmt.Errorf("getPhysicalAdapters: %w", err)
	}
	return adapters, nil
}

func getTargetInterface() (uint32, error) {
	// 1. Try the "Easy Way" (works if a default route exists)
	idx, err := getDefaultIfIndex()
	if err == nil {
		return idx, nil
	}

	// 2. Typically error 1231 (routing table has no default route): ask which adapter.
	fmt.Printf("No existing default route found (%v), so selecting the adapter manually.\n", err)
	adapter, err := UserSelectInterface()
	if err != nil {
		return 0, fmt.Errorf("failed selecting adapter: %w", err)
	}
	return adapter.Index, nil
}

func UserSelectInterface() (NetworkAdapter, error) {
	adapters, err := getPhysicalAdapters()
	if err != nil {
		return NetworkAdapter{}, fmt.Errorf("could not enumerate the active physical adapters: %w", err)
	}
	if len(adapters) == 0 {
		return NetworkAdapter{}, errors.New("could not find any active physical adapters (ie. LAN cable not plugged in)")
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
		line := strings.TrimPrefix(scanner.Text(), "\uFEFF") // Notepad & co. may prepend a UTF-8 BOM

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
		return "", fmt.Errorf("no gateway IP found in %q", gwFile)
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
		ifIndex, err := getTargetInterface()
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
			if errors.Is(err, errnoNotFound) {
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
			if errors.Is(err, errnoNotFound) {
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

// Process exit codes. 2 is deliberately unused (Go itself exits with 2 on an unrecovered panic) and so is 130
// (run.bat treats that one as "restart me").
const (
	exitOK          = 0
	exitFailure     = 1 // an API call or other runtime operation failed
	exitConfig      = 3 // missing/invalid gateway.cfg contents
	exitNotAdmin    = 4 // not elevated
	exitUnsupported = 5 // eg. DHCP is enabled on the chosen interface
)

func main() {
	// run() returns instead of calling os.Exit itself so that all of its defers (gateway removal, console mode
	// restore, "press any key") get to run first.
	os.Exit(run())
}

func run() int {
	// Top-level defer: Executes last! Restored console state guarantees exclusive, clean access here.
	defer func() {
		if !wincoe.WaitAnyKeyIfInteractive() {
			fmt.Println("Didn't wait for keypress due to not an interactive/terminal.")
		}
	}()

	// Both listings are informational only, so one failing doesn't skip the other.
	if listErr := listIfIndexes(); listErr != nil {
		redPrintf("Error listing interfaces: %v\n", listErr)
	}
	if listErr := listInterfaceIPs(); listErr != nil {
		redPrintf("Error listing interface IPs: %v\n", listErr)
	}

	ifIndex, err := getTargetInterfaceWithRetry()
	if err != nil {
		redPrintf("Cannot get default interface: %v\n", err)
		return exitFailure
	}
	fmt.Printf("default interface index: %d\n", ifIndex)

	guid, err := getInterfaceGUID(ifIndex)
	if err != nil {
		redPrintf("Cannot resolve the GUID of interface %d: %v\n", ifIndex, err)
		return exitFailure
	}

	if err = checkInterfaceDHCPDisabled(guid); err != nil {
		if errors.Is(err, errDHCPEnabled) {
			redPrintf("%v\n", err)
			return exitUnsupported
		}
		yellowPrintf("Warning: couldn't verify that DHCP is disabled on interface %s: %v\n", guid, err)
	}

	if count, countErr := countLegacyPersistentRoutes(); countErr != nil {
		yellowPrintf("Warning: couldn't check the legacy persistent routes: %v\n", countErr)
	} else if count > 0 {
		yellowPrintf("Warning: the legacy registry key HKLM\\%s isn't empty (%d value(s)); those routes survive reboots and can conflict with this tool (see 'Persistent Routes' in 'route print -4').\n",
			persistentRoutesKeyPath, count)
	}

	exists, existingGW, err := hasDefaultGateway(ifIndex)
	if err != nil {
		redPrintf("Cannot check for an existing default gateway: %v\n", err)
		return exitFailure
	}
	if exists {
		redPrintf("Warning: default gateway already exists on this interface: %s (raw 0x%08X)\n", ipv4StringLE(existingGW), existingGW)
	}

	// Example gateway, replace with the “real” GW you want
	wantedGW, err := getWantedGW()
	if err != nil {
		redPrintf("need to know which gw to set: %v\n", err)
		return exitConfig
	}
	fmt.Printf("Read gw '%s' from file '%s'\n", wantedGW, gwFile)

	targetGW, err := ipv4ToUint32LE(wantedGW)
	if err != nil {
		redPrintf("Failed to convert wanted gw IP %s into uint32: %v\n", wantedGW, err)
		return exitConfig
	}
	if targetGW == 0 || targetGW == ^uint32(0) {
		redPrintf("The wanted gw %s (0.0.0.0 or 255.255.255.255) isn't a usable gateway address\n", wantedGW)
		return exitConfig
	}

	fmt.Printf("The gateway that we want is %s aka 0x%08X\n",
		ipv4StringLE(targetGW), targetGW)

	token := windows.GetCurrentProcessToken()
	if !token.IsElevated() {
		redPrintf("Must run as admin to effect changes!\n")
		return exitNotAdmin
	}

	// 1. Put Stdin into raw mode so we can capture Ctrl+R instantly (without hitting Enter)
	// We also clear ENABLE_PROCESSED_INPUT, so Ctrl+C arrives as the plain byte 3 (handled in the loop below) instead of a signal.
	var oldMode uint32
	if modeErr := windows.GetConsoleMode(windows.Stdin, &oldMode); modeErr != nil {
		redPrintf("Warning: GetConsoleMode failed, Ctrl+R raw-mode toggling won't work: %v\n", modeErr)
	} else {
		newMode := oldMode &^ (windows.ENABLE_LINE_INPUT | windows.ENABLE_ECHO_INPUT | windows.ENABLE_PROCESSED_INPUT)
		if setErr := windows.SetConsoleMode(windows.Stdin, newMode); setErr != nil {
			redPrintf("Warning: SetConsoleMode(raw) failed, Ctrl+R raw-mode toggling won't work: %v\n", setErr)
		} else {
			// Executes 2nd on exit, restoring cooked console
			defer func() {
				if restoreErr := windows.SetConsoleMode(windows.Stdin, oldMode); restoreErr != nil {
					redPrintf("Warning: failed to restore original console mode on exit: %v\n", restoreErr)
				}
			}()
		}
	}

	var isActive bool
	// stateMu guards isActive/removeActiveGateway/removeDirectGWRoute: the console ctrl handler calls deactivate()
	// on a different OS thread than the main loop's activate()/deactivate().
	var stateMu sync.Mutex

	// 2. Wrap routing logic into an activate closure
	activate := func() {
		stateMu.Lock()
		defer stateMu.Unlock()
		if clearErr := clearPersistentGatewayForIndex(ifIndex); clearErr != nil {
			redPrintf("Failed to delete persistent gateway(ie. the one set in LAN adapter settings, seen by 'route print' under 'Persistent Routes'), err: %v\n", clearErr)
			return //XXX: yes, we don't wanna continue if this fails
		}
		if setErr := forceSetDefaultGateway(targetGW, ifIndex); setErr != nil {
			redPrintf("Failed to set gateway: %v\n", setErr)
			return
		}
		isActive = true
		cautionPrintf("\n>>> Gateway is ACTIVE. Internet is routed.\n")
	}

	// 3. Wrap cleanup logic into a deactivate closure
	deactivate := func() {
		stateMu.Lock()
		defer stateMu.Unlock()
		onlinkgatewayremoval(targetGW, ifIndex, isActive)
		defaultgatewayremoval(targetGW, ifIndex, isActive)

		isActive = false
		yellowPrintf("\n>>> Gateway is INACTIVE. Internet is blocked.\n")
	}

	// Executes 1st on exit: Triggers cleanup if the loop breaks while active.
	// Guarantee cleanup on exit (handles Ctrl+C or normal return)
	defer deactivate()

	// Bind our local cleanup logic to the package-level anchor the console ctrl handler uses
	globalCleanup = deactivate

	// Register the callback with Windows via kernel32.dll using wincoe's bound wrapper
	if res := wincoe.RegisterCtrlHandler(consoleCtrlHandler); res.Failed() {
		redPrintf("CRITICAL: Failed to register console control handler: %v\n", res.Err)
		return exitFailure
	}
	// Just a quiet sanity check confirmation during startup
	fmt.Println("OS termination handler successfully registered.")

	// Initial Activation
	activate()

	// 4. THE WAITING ROOM
	cautionPrintf(">>> Press Ctrl+R to toggle state. Press Ctrl+C to disconnect and exit.\n")

	// Sequential loop on the main goroutine
	buf := make([]byte, 1)
	for {
		n, readErr := os.Stdin.Read(buf)
		if readErr != nil || n == 0 {
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				redPrintf("Reading stdin failed, cleaning up and exiting: %v\n", readErr)
				return exitFailure
			}
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
	return exitOK
}
