package fingerprint

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fixture struct {
	Banner string
	Prompt string
	Probe  string
}

func loadFixture(t *testing.T, name string) fixture {
	t.Helper()

	path := filepath.Join("testdata", name+".txt")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", name, err)
	}

	sections := map[string]*strings.Builder{
		"banner": new(strings.Builder),
		"prompt": new(strings.Builder),
		"probe":  new(strings.Builder),
	}

	current := ""
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "---") {
			lower := strings.ToLower(strings.TrimSpace(strings.Trim(line, "-")))
			switch {
			case strings.Contains(lower, "banner"):
				current = "banner"
			case strings.Contains(lower, "prompt"):
				current = "prompt"
			case strings.Contains(lower, "probe"):
				current = "probe"
			default:
				current = ""
			}
			continue
		}

		if current == "" {
			continue
		}
		sections[current].WriteString(line)
		sections[current].WriteByte('\n')
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner error: %v", err)
	}

	return fixture{
		Banner: strings.TrimSpace(sections["banner"].String()),
		Prompt: strings.TrimSpace(sections["prompt"].String()),
		Probe:  strings.TrimSpace(sections["probe"].String()),
	}
}

func TestAnalyzeFixtures(t *testing.T) {
	cases := []struct {
		name              string
		fixture           string
		wantVendor        string
		wantOS            string
		wantStage         Stage
		wantMinConfidence float64
		wantModel         string
	}{
		{name: "Cisco IOS", fixture: "cisco_ios", wantVendor: "Cisco", wantOS: "IOS", wantStage: StagePrompt, wantMinConfidence: 0.8, wantModel: "WS-C2960-24TT-L"},
		{name: "Cisco ASA", fixture: "cisco_asa", wantVendor: "Cisco", wantOS: "ASA", wantStage: StagePrompt, wantMinConfidence: 0.8, wantModel: "ASA5515"},
		{name: "Cisco NX-OS", fixture: "cisco_nxos", wantVendor: "Cisco", wantOS: "NX-OS", wantStage: StagePrompt, wantMinConfidence: 0.8, wantModel: "cisco Nexus 93180YC-FX Chassis"},
		{name: "Cisco IOS-XR", fixture: "cisco_iosxr", wantVendor: "Cisco", wantOS: "IOS-XR", wantStage: StagePrompt, wantMinConfidence: 0.8},
		{name: "Aruba CX", fixture: "aruba_aos_cx", wantVendor: "Aruba", wantOS: "AOS-CX", wantStage: StagePrompt, wantMinConfidence: 0.8, wantModel: "Aruba 8320 Switch Series"},
		{name: "Aruba AOS-S", fixture: "aruba_aos_s", wantVendor: "Aruba", wantOS: "AOS-S", wantStage: StagePrompt, wantMinConfidence: 0.8},
		{name: "JUNOS", fixture: "junos", wantVendor: "Juniper", wantOS: "JUNOS", wantStage: StagePrompt, wantMinConfidence: 0.75, wantModel: "mx204"},
		{name: "MikroTik", fixture: "mikrotik", wantVendor: "MikroTik", wantOS: "RouterOS", wantStage: StagePrompt, wantMinConfidence: 0.75, wantModel: "CRS328-24P-4S+"},
		{name: "EdgeOS", fixture: "edgeos", wantVendor: "Ubiquiti", wantOS: "EdgeOS", wantStage: StagePrompt, wantMinConfidence: 0.7, wantModel: "EdgeRouter"},
		{name: "FortiGate", fixture: "fortigate", wantVendor: "Fortinet", wantOS: "FortiOS", wantStage: StagePrompt, wantMinConfidence: 0.75, wantModel: "FortiGate-60E v6.4.9,build2044"},
		{name: "Palo Alto", fixture: "paloalto", wantVendor: "PaloAlto", wantOS: "PAN-OS", wantStage: StagePrompt, wantMinConfidence: 0.75, wantModel: "PA-220"},
		{name: "Huawei VRP", fixture: "huawei_vrp", wantVendor: "Huawei", wantOS: "VRP", wantStage: StagePrompt, wantMinConfidence: 0.75, wantModel: "S5720-28X-SI-AC"},
		{name: "HPE Comware", fixture: "hpe_comware", wantVendor: "HPE", wantOS: "Comware", wantStage: StagePrompt, wantMinConfidence: 0.75, wantModel: "HPE 5130-24G-PoE+-4SFP+ EI"},
		{name: "Dell OS10", fixture: "dell_os10", wantVendor: "Dell", wantOS: "OS10", wantStage: StagePrompt, wantMinConfidence: 0.7, wantModel: "Dell S5248F-ON"},
		{name: "Brocade", fixture: "brocade_fastiron", wantVendor: "Brocade/Extreme", wantOS: "FastIron", wantStage: StagePrompt, wantMinConfidence: 0.75, wantModel: "ICX7250-48P"},
		{name: "VyOS", fixture: "vyos", wantVendor: "VyOS", wantOS: "VyOS", wantStage: StagePrompt, wantMinConfidence: 0.75, wantModel: "1.4-rolling-20240220"},
		{name: "OpenWrt", fixture: "openwrt", wantVendor: "OpenWrt", wantOS: "OpenWrt", wantStage: StagePrompt, wantMinConfidence: 0.7, wantModel: "OpenWrt 22.03.0"},
		{name: "pfSense", fixture: "pfsense", wantVendor: "pfSense/OPNsense", wantOS: "pfSense", wantStage: StagePrompt, wantMinConfidence: 0.7, wantModel: "pfSense"},
		{name: "U-Boot", fixture: "uboot", wantVendor: "Bootloader", wantOS: "U-Boot", wantStage: StageBoot, wantMinConfidence: 0.6},
		{name: "ROMMON", fixture: "rommon", wantVendor: "Bootloader", wantOS: "ROMMON", wantStage: StageBoot, wantMinConfidence: 0.6},
		{name: "GRUB", fixture: "grub", wantVendor: "Bootloader", wantOS: "GRUB", wantStage: StageBoot, wantMinConfidence: 0.6},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			fx := loadFixture(t, tt.fixture)
			rx := strings.TrimSpace(fx.Banner)
			if fx.Prompt != "" {
				rx = strings.TrimSpace(rx + "\n" + fx.Prompt)
			}

			stage, candidates := Analyze(rx, fx.Prompt)
			if stage != tt.wantStage {
				t.Fatalf("stage = %s, want %s", stage, tt.wantStage)
			}

			if len(candidates) == 0 {
				t.Fatalf("no candidates produced for %s", tt.name)
			}

			top := candidates[0]
			if top.Vendor != tt.wantVendor {
				t.Fatalf("vendor = %q, want %q", top.Vendor, tt.wantVendor)
			}
			if top.OS != tt.wantOS {
				t.Fatalf("os = %q, want %q", top.OS, tt.wantOS)
			}

			res := Finalize(stage, candidates, rx, fx.Prompt, fx.Probe)
			if res.Confidence < tt.wantMinConfidence {
				t.Fatalf("confidence = %.2f, want >= %.2f", res.Confidence, tt.wantMinConfidence)
			}

			if tt.wantModel != "" && !strings.Contains(res.Model, tt.wantModel) {
				t.Fatalf("model %q does not contain %q", res.Model, tt.wantModel)
			}
		})
	}
}

func TestNegativeFixtures(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
	}{
		{name: "Ambiguous login", fixture: "ambiguous_login"},
		{name: "Generic shell", fixture: "generic_shell"},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			fx := loadFixture(t, tt.fixture)
			rx := strings.TrimSpace(fx.Banner)
			if fx.Prompt != "" {
				rx = strings.TrimSpace(rx + "\n" + fx.Prompt)
			}

			stage, candidates := Analyze(rx, fx.Prompt)
			if tt.name == "Ambiguous login" && stage != StageLogin {
				t.Fatalf("expected StageLogin, got %s", stage)
			}

			res := Finalize(stage, candidates, rx, fx.Prompt, fx.Probe)
			if res.Confidence > 0.5 {
				t.Fatalf("expected low confidence, got %.2f", res.Confidence)
			}
		})
	}
}
