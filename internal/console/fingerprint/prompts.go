package fingerprint

import "regexp"

type PromptPattern struct {
	Name   string
	Regex  *regexp.Regexp
	Vendor string
	OS     string
}

var (
	bootPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bU-Boot\b`),
		regexp.MustCompile(`(?i)rommon \d+ >`),
		regexp.MustCompile(`(?i)GNU GRUB`),
	}

	loginPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)^(username|user name|login|password):\s*$`),
		regexp.MustCompile(`(?i)amnesiac`),
	}

	promptPatterns = []PromptPattern{
		{Name: "cisco_ios", Regex: regexp.MustCompile(`(?m)^([A-Za-z0-9._-]+)(\((config[^\)]*)\))?[#>] ?$`), Vendor: "Cisco", OS: "IOS"},
		{Name: "cisco_asa", Regex: regexp.MustCompile(`(?m)^ciscoasa(?:\([^\)]*\))?[#>] ?$`), Vendor: "Cisco", OS: "ASA"},
		{Name: "cisco_nxos", Regex: regexp.MustCompile(`(?m)^(Nexus|switch)[#>] ?$`), Vendor: "Cisco", OS: "NX-OS"},
		{Name: "cisco_iosxr", Regex: regexp.MustCompile(`(?m)^RP/\d+/\S+:\S+# ?$`), Vendor: "Cisco", OS: "IOS-XR"},
		{Name: "junos", Regex: regexp.MustCompile(`(?m)^[\w\-]+@[\w\-.]+[>#] ?$`), Vendor: "Juniper", OS: "JUNOS"},
		{Name: "aruba_cx", Regex: regexp.MustCompile(`(?mi)^(mgr|admin|[A-Za-z0-9._-]+)# ?$`), Vendor: "Aruba", OS: "AOS-CX"},
		{Name: "aruba_aos_s", Regex: regexp.MustCompile(`(?m)^(HP|Aruba|ProCurve)[\w\-]*[>#] ?$`), Vendor: "Aruba", OS: "AOS-S"},
		{Name: "mikrotik", Regex: regexp.MustCompile(`(?m)^\[[^\]]+\]\s?> ?$`), Vendor: "MikroTik", OS: "RouterOS"},
		{Name: "edgeos", Regex: regexp.MustCompile(`(?m)^[\w\-]+@[\w\-.]+(:~)?[$#] ?$`), Vendor: "Ubiquiti", OS: "EdgeOS"},
		{Name: "fortigate", Regex: regexp.MustCompile(`(?m)^FGT\w*\s?[#>] ?$`), Vendor: "Fortinet", OS: "FortiOS"},
		{Name: "paloalto", Regex: regexp.MustCompile(`(?m)^[\w\-]+@PA-\w+[>#] ?$`), Vendor: "PaloAlto", OS: "PAN-OS"},
		{Name: "huawei_vrp", Regex: regexp.MustCompile(`(?m)^(<[Hh][PpEe]?[^>]*>|\[[Hh].*?\])$`), Vendor: "Huawei", OS: "VRP"},
		{Name: "comware", Regex: regexp.MustCompile(`(?m)^((<|\[)HPE?.*?(>|\]))$`), Vendor: "HPE", OS: "Comware"},
		{Name: "brocade_fastiron", Regex: regexp.MustCompile(`(?m)^(ICX|BR-CD|FastIron).*?[#>] ?$`), Vendor: "Brocade/Extreme", OS: "FastIron"},
		{Name: "vyos", Regex: regexp.MustCompile(`(?m)^vyos@.*[$#] ?$`), Vendor: "VyOS", OS: "VyOS"},
		{Name: "openwrt", Regex: regexp.MustCompile(`(?m)^root@OpenWrt:~#$`), Vendor: "OpenWrt", OS: "OpenWrt"},
		{Name: "pfsense", Regex: regexp.MustCompile(`(?m)^root@pfSense:~ #$`), Vendor: "pfSense/OPNsense", OS: "pfSense"},
		{Name: "generic_hash", Regex: regexp.MustCompile(`(?m)^.*[>#$] ?$`), Vendor: "Generic", OS: "Shell"},
	}

	lineSplitRe = regexp.MustCompile("\n+")
)

// DetectStage infers the interaction stage based on RX and prompt line.
func DetectStage(rx, promptLine string) Stage {
	for _, re := range bootPatterns {
		if re.MatchString(rx) {
			return StageBoot
		}
	}

	if matchPrompt(promptLine) != nil {
		return StagePrompt
	}

	lines := lineSplitRe.Split(rx, -1)
	for i := len(lines) - 1; i >= 0 && i >= len(lines)-4; i-- {
		line := lines[i]
		for _, re := range loginPatterns {
			if re.MatchString(line) {
				return StageLogin
			}
		}
	}

	return StagePreLogin
}

func matchPrompt(promptLine string) *PromptPattern {
	if promptLine == "" {
		return nil
	}
	for i := range promptPatterns {
		if promptPatterns[i].Regex.MatchString(promptLine) {
			return &promptPatterns[i]
		}
	}
	return nil
}

// PromptPatterns returns the known prompt heuristics.
func PromptPatterns() []PromptPattern {
	return promptPatterns
}
