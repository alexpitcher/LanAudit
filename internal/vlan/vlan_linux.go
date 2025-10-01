//go:build linux

package vlan

import (
	"context"
	"fmt"
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

// TestVLANs is not implemented on Linux
func TestVLANs(ctx context.Context, phy string, vlans []int, keep bool, consentToken string) ([]LeaseResult, error) {
	return nil, fmt.Errorf("VLAN testing not implemented on Linux")
}
