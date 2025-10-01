// go:build darwin
//go:build darwin

package vlan

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/alexpitcher/LanAudit/internal/consent"
)

// LeaseResult contains DHCP lease information for a VLAN
type LeaseResult struct {
	VLAN   int      `json:"vlan"`
	IP     string   `json:"ip"`
	Router string   `json:"router"`
	DNS    []string `json:"dns"`
	Err    string   `json:"error,omitempty"`
}

const ConsentToken = "VLAN-YES"

// TestVLANs creates ephemeral VLAN interfaces and tests DHCP
func TestVLANs(ctx context.Context, phy string, vlans []int, keep bool, consentToken string) ([]LeaseResult, error) {
	// Validate consent
	if err := consent.Confirm(consentToken, ConsentToken); err != nil {
		return nil, fmt.Errorf("consent required: %w", err)
	}

	// Only supported on macOS
	if runtime.GOOS != "darwin" {
		return nil, fmt.Errorf("VLAN testing only supported on macOS (current OS: %s)", runtime.GOOS)
	}

	// Log consent
	meta := map[string]string{
		"physical_interface": phy,
		"vlans":              fmt.Sprintf("%v", vlans),
		"keep":               strconv.FormatBool(keep),
	}
	if err := consent.Log("VLAN_TEST", meta); err != nil {
		return nil, fmt.Errorf("failed to log consent: %w", err)
	}

	results := make([]LeaseResult, 0, len(vlans))

	for _, vlanID := range vlans {
		result := testSingleVLAN(ctx, phy, vlanID, keep)
		results = append(results, result)
	}

	return results, nil
}

// testSingleVLAN tests a single VLAN interface
func testSingleVLAN(ctx context.Context, phy string, vlanID int, keep bool) LeaseResult {
	result := LeaseResult{VLAN: vlanID}
	ifaceName := fmt.Sprintf("vlan%d", vlanID)

	// Create VLAN interface
	if err := runCommand(ctx, "ifconfig", ifaceName, "create"); err != nil {
		result.Err = fmt.Sprintf("create failed: %v", err)
		return result
	}

	// If not keeping, ensure cleanup
	if !keep {
		defer runCommand(context.Background(), "ifconfig", ifaceName, "destroy")
	}

	// Associate with physical interface and VLAN ID
	if err := runCommand(ctx, "ifconfig", ifaceName, "vlan", strconv.Itoa(vlanID), "vlandev", phy); err != nil {
		result.Err = fmt.Sprintf("vlan config failed: %v", err)
		return result
	}

	// Bring interface up
	if err := runCommand(ctx, "ifconfig", ifaceName, "up"); err != nil {
		result.Err = fmt.Sprintf("bring up failed: %v", err)
		return result
	}

	// Request DHCP
	if err := runCommand(ctx, "ipconfig", "set", ifaceName, "DHCP"); err != nil {
		result.Err = fmt.Sprintf("DHCP request failed: %v", err)
		return result
	}

	// Get DHCP packet info
	output, err := runCommandOutput(ctx, "ipconfig", "getpacket", ifaceName)
	if err != nil {
		result.Err = fmt.Sprintf("getpacket failed: %v", err)
		return result
	}

	// Parse DHCP response
	parseIPConfigPacket(output, &result)

	return result
}

// runCommand executes a command and returns error if it fails
func runCommand(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Run()
}

// runCommandOutput executes a command and returns its output
func runCommandOutput(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// parseIPConfigPacket extracts DHCP lease information from ipconfig getpacket output
func parseIPConfigPacket(output string, result *LeaseResult) {
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse yiaddr (your IP address)
		if strings.HasPrefix(line, "yiaddr") {
			re := regexp.MustCompile(`yiaddr\s*=\s*(\S+)`)
			if matches := re.FindStringSubmatch(line); len(matches) >= 2 {
				result.IP = matches[1]
			}
		}

		// Parse router
		if strings.HasPrefix(line, "router") {
			re := regexp.MustCompile(`router.*?{\s*([0-9.]+)`)
			if matches := re.FindStringSubmatch(line); len(matches) >= 2 {
				result.Router = matches[1]
			}
		}

		// Parse DNS servers
		if strings.HasPrefix(line, "domain_name_server") {
			re := regexp.MustCompile(`domain_name_server.*?{\s*([^}]+)`)
			if matches := re.FindStringSubmatch(line); len(matches) >= 2 {
				servers := strings.Fields(strings.ReplaceAll(matches[1], ",", " "))
				result.DNS = servers
			}
		}
	}

	// If we got an IP, consider it successful
	if result.IP == "" {
		result.Err = "no DHCP lease obtained"
	}
}
