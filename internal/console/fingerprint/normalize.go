package fingerprint

import (
	"regexp"
	"strings"
)

var ansiRegexp = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// Normalize removes ANSI sequences and harmonises newlines.
func Normalize(in string) string {
	if in == "" {
		return ""
	}
	cleaned := ansiRegexp.ReplaceAllString(in, "")
	cleaned = strings.ReplaceAll(cleaned, "\r\n", "\n")
	cleaned = strings.ReplaceAll(cleaned, "\r", "\n")
	cleaned = strings.ReplaceAll(cleaned, "\u0000", "")
	return cleaned
}

// ExtractLastPromptLine returns the last non-empty line from the RX buffer.
func ExtractLastPromptLine(rx string) string {
	lines := strings.Split(rx, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(lines[i])
		if candidate != "" {
			return candidate
		}
	}
	return ""
}
