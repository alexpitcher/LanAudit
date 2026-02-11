package net

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// Iface represents a network interface
type Iface struct {
	Name         string
	HardwareAddr string
	MTU          int
	IsVirtual    bool
	Flags        net.Flags
	BytesRx      uint64
	BytesTx      uint64
	PacketsRx    uint64
	PacketsTx    uint64
	Description  string
}

// InterfaceDetails contains detailed information about an interface
type InterfaceDetails struct {
	Name           string
	IPs            []string
	MAC            string
	MTU            int
	DefaultGateway string
	DNSServers     []string
	LinkUp         bool
	BytesRx        uint64
	BytesTx        uint64
	PacketsRx      uint64
	PacketsTx      uint64
	Speed          string
	Type           string
}

// ListInterfaces returns all network interfaces
func ListInterfaces() ([]Iface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	result := make([]Iface, 0, len(ifaces))
	for _, iface := range ifaces {
		mac := iface.HardwareAddr.String()
		isVirtual := isVirtualInterface(iface.Name, mac)

		// Get stats
		stats, _ := getInterfaceStats(iface.Name)

		result = append(result, Iface{
			Name:         iface.Name,
			HardwareAddr: mac,
			MTU:          iface.MTU,
			IsVirtual:    isVirtual,
			Flags:        iface.Flags,
			BytesRx:      stats.BytesRx,
			BytesTx:      stats.BytesTx,
			PacketsRx:    stats.PacketsRx,
			PacketsTx:    stats.PacketsTx,
			Description:  getInterfaceDescription(iface.Name),
		})
	}

	return result, nil
}

// ListUserInterfaces returns only interfaces suitable for user selection
// Filters out loopback, bridge, tunnel, and other virtual interfaces
func ListUserInterfaces() ([]Iface, error) {
	all, err := ListInterfaces()
	if err != nil {
		return nil, err
	}

	var filtered []Iface
	for _, iface := range all {
		// Skip loopback
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// Skip interfaces without hardware addresses (most virtual)
		if iface.HardwareAddr == "" {
			continue
		}

		// Skip known virtual prefixes
		if isConfusingInterface(iface.Name) {
			continue
		}

		// Skip down interfaces unless they have a MAC (might come up)
		if iface.Flags&net.FlagUp == 0 && iface.HardwareAddr == "" {
			continue
		}

		filtered = append(filtered, iface)
	}

	return filtered, nil
}

// isConfusingInterface filters out bridge, tunnel, and container interfaces
func isConfusingInterface(name string) bool {
	confusingPrefixes := []string{
		"bridge", "docker", "veth", "vmnet", "vmenet", "vboxnet",
		"utun", "awdl", "llw", "p2p", "ap", "anpi",
	}

	lowerName := strings.ToLower(name)
	for _, prefix := range confusingPrefixes {
		if strings.HasPrefix(lowerName, prefix) {
			return true
		}
	}
	return false
}

// getInterfaceDescription returns a human-friendly description
func getInterfaceDescription(name string) string {
	descriptions := map[string]string{
		"en0":   "Wi-Fi/Built-in Ethernet",
		"en1":   "Thunderbolt Ethernet",
		"en2":   "Thunderbolt Bridge",
		"en3":   "USB Ethernet",
		"eth0":  "Primary Ethernet",
		"eth1":  "Secondary Ethernet",
		"wlan0": "Wireless",
	}

	if desc, ok := descriptions[name]; ok {
		return desc
	}

	// Generic descriptions for unmapped interfaces
	if strings.HasPrefix(name, "en") {
		// en4+ are usually Thunderbolt/USB adapters
		if len(name) > 2 && name[2] >= '4' {
			return "Thunderbolt/USB Adapter"
		}
		return "Built-in Network"
	}
	if strings.HasPrefix(name, "eth") {
		return "Ethernet"
	}
	if strings.HasPrefix(name, "wlan") {
		return "Wireless"
	}

	return "Network Adapter"
}

// GetInterfaceDetails retrieves detailed information for a specific interface
func GetInterfaceDetails(name string) (*InterfaceDetails, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	ips := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			ips = append(ips, ipnet.IP.String())
		}
	}

	gateway, err := getDefaultGateway()
	if err != nil {
		gateway = ""
	}

	dns, err := getDNSServers()
	if err != nil {
		dns = []string{}
	}

	linkUp := iface.Flags&net.FlagUp != 0

	// Get stats
	stats, _ := getInterfaceStats(name)

	return &InterfaceDetails{
		Name:           name,
		IPs:            ips,
		MAC:            iface.HardwareAddr.String(),
		MTU:            iface.MTU,
		DefaultGateway: gateway,
		DNSServers:     dns,
		LinkUp:         linkUp,
		BytesRx:        stats.BytesRx,
		BytesTx:        stats.BytesTx,
		PacketsRx:      stats.PacketsRx,
		PacketsTx:      stats.PacketsTx,
		Speed:          "", // Loaded asynchronously
		Type:           "", // Loaded asynchronously
	}, nil
}

// GetExtendedInterfaceDetails retrieves slow-to-load information (Speed, Type)
func GetExtendedInterfaceDetails(name string) (speed string, ifaceType string, err error) {
	return getExtendedInterfaceInfo(name)
}

// IsRoot checks if running with root/sudo privileges
func IsRoot() bool {
	return os.Geteuid() == 0
}

// HasPcapPermissions checks if we have packet capture permissions
func HasPcapPermissions() bool {
	return IsRoot()
}

// isVirtualInterface attempts to determine if an interface is virtual
func isVirtualInterface(name, mac string) bool {
	// Common virtual interface patterns
	virtualPrefixes := []string{"vlan", "lo", "bridge", "docker", "veth", "tap", "tun", "utun"}
	for _, prefix := range virtualPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}

	// Empty MAC often indicates virtual
	if mac == "" {
		return true
	}

	return false
}

// getDefaultGateway retrieves the default gateway (macOS implementation)
func getDefaultGateway() (string, error) {
	cmd := exec.Command("route", "-n", "get", "default")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return parseDefaultGateway(string(output))
}

// parseDefaultGateway extracts gateway IP from route output
func parseDefaultGateway(output string) (string, error) {
	re := regexp.MustCompile(`gateway:\s+(\S+)`)
	matches := re.FindStringSubmatch(output)
	if len(matches) < 2 {
		return "", fmt.Errorf("gateway not found in route output")
	}
	return matches[1], nil
}

// getDNSServers retrieves DNS servers from system configuration
func getDNSServers() ([]string, error) {
	// Try /etc/resolv.conf first
	dns, err := parseDNSFromResolvConf("/etc/resolv.conf")
	if err == nil && len(dns) > 0 {
		return dns, nil
	}

	// Fallback to scutil on macOS
	return getDNSFromScutil()
}

// parseDNSFromResolvConf reads DNS servers from resolv.conf
func parseDNSFromResolvConf(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var dns []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				dns = append(dns, fields[1])
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return dns, nil
}

// getDNSFromScutil uses scutil to get DNS servers on macOS
func getDNSFromScutil() ([]string, error) {
	cmd := exec.Command("scutil", "--dns")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	return parseScutilDNS(string(output)), nil
}

// parseScutilDNS extracts DNS servers from scutil output
func parseScutilDNS(output string) []string {
	var dns []string
	seen := make(map[string]bool)

	re := regexp.MustCompile(`nameserver\[\d+\]\s*:\s*(\S+)`)
	matches := re.FindAllStringSubmatch(output, -1)

	for _, match := range matches {
		if len(match) >= 2 && !seen[match[1]] {
			dns = append(dns, match[1])
			seen[match[1]] = true
		}
	}

	return dns
}
