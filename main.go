package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapiDLL              = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetBestInterface     = iphlpapiDLL.NewProc("GetBestInterface")
	procGetIpForwardTable    = iphlpapiDLL.NewProc("GetIpForwardTable")
	procCreateIpForwardEntry = iphlpapiDLL.NewProc("CreateIpForwardEntry")
	procSetIpForwardEntry    = iphlpapiDLL.NewProc("SetIpForwardEntry")
	procDeleteIpForwardEntry = iphlpapiDLL.NewProc("DeleteIpForwardEntry")
)

// MIB_IPFORWARDROW struct for SetIpForwardEntry
type MIB_IPFORWARDROW struct {
	DwForwardDest      uint32
	DwForwardMask      uint32
	DwForwardPolicy    uint32
	DwForwardNextHop   uint32
	DwForwardIfIndex   uint32
	DwForwardType      uint32
	DwForwardProto     uint32
	DwForwardAge       uint32
	DwForwardNextHopAS uint32
	DwForwardMetric1   uint32
	DwForwardMetric2   uint32
	DwForwardMetric3   uint32
	DwForwardMetric4   uint32
	DwForwardMetric5   uint32
}

// Convert IPv4 string to uint32 in network byte order
func ipv4ToUint32(ip string) uint32 {
	var b [4]byte
	fmt.Sscanf(ip, "%d.%d.%d.%d", &b[0], &b[1], &b[2], &b[3])
	return binary.LittleEndian.Uint32(b[:])
}

// Set default gateway
func setDefaultGateway(gw uint32, ifIndex uint32) error {
	row := MIB_IPFORWARDROW{
		DwForwardDest:    0, // 0.0.0.0
		DwForwardMask:    0, // 0.0.0.0
		DwForwardNextHop: gw,
		DwForwardIfIndex: ifIndex,
		DwForwardType:    4, // INDIRECT
		DwForwardProto:   3, // NETMGMT
		DwForwardMetric1: 1,
	}
	ret, _, err := procSetIpForwardEntry.Call(uintptr(unsafe.Pointer(&row)))
	if ret != 0 {
		return fmt.Errorf("SetIpForwardEntry failed: %v", err)
	}
	return nil
}

// Delete default gateway
func deleteDefaultGateway(ifIndex uint32) error {
	row := MIB_IPFORWARDROW{
		DwForwardDest:    0,
		DwForwardMask:    0,
		DwForwardIfIndex: ifIndex,
	}
	ret, _, err := procDeleteIpForwardEntry.Call(uintptr(unsafe.Pointer(&row)))
	if ret != 0 {
		return fmt.Errorf("DeleteIpForwardEntry failed: %v", err)
	}
	return nil
}

// Get the best interface index for default route
func getDefaultIfIndex() (uint32, error) {
	var ifIndex uint32
	ret, _, err := procGetBestInterface.Call(uintptr(ipv4ToUint32("8.8.8.8")), uintptr(unsafe.Pointer(&ifIndex)))
	if ret != 0 {
		return 0, fmt.Errorf("GetBestInterface failed: %v", err)
	}
	return ifIndex, nil
}

func main() {
	ifIndex, err := getDefaultIfIndex()
	if err != nil {
		fmt.Println("Cannot get default interface:", err)
		return
	}

	// Warn if there’s already a gateway
	fmt.Println("Warning: Make sure adapter default gateway is empty to avoid conflicts.")

	// Example gateway, replace with the “real” GW you want
	gw := ipv4ToUint32("192.168.1.1")

	// Set proper gateway
	if err := setDefaultGateway(gw, ifIndex); err != nil {
		fmt.Println("Failed to set gateway:", err)
		return
	}
	fmt.Println("Default gateway set. Press Ctrl+C to exit and remove it.")

	// Catch CTRL+C to remove gateway on exit
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	if err := deleteDefaultGateway(ifIndex); err != nil {
		fmt.Println("Failed to delete gateway:", err)
	} else {
		fmt.Println("Default gateway removed, network disabled.")
	}
}
