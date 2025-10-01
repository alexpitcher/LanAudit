package consent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	ConsentLogFile = "consent.log"
)

// Confirm validates user consent with a required token
func Confirm(userInput, requiredToken string) error {
	if strings.TrimSpace(userInput) != requiredToken {
		return fmt.Errorf("consent denied: expected '%s', got '%s'", requiredToken, userInput)
	}
	return nil
}

// Log appends a consent action to the log file
func Log(action string, meta map[string]string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	logDir := filepath.Join(home, ".lanaudit")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return err
	}

	logPath := filepath.Join(logDir, ConsentLogFile)

	// Build log entry
	timestamp := time.Now().UTC().Format(time.RFC3339)
	metaParts := make([]string, 0, len(meta))
	for k, v := range meta {
		metaParts = append(metaParts, fmt.Sprintf("%s=%s", k, v))
	}
	metaStr := strings.Join(metaParts, " ")

	entry := fmt.Sprintf("%s | %s | %s\n", timestamp, action, metaStr)

	// Append to file
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(entry)
	return err
}

// GetLogPath returns the path to the consent log
func GetLogPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".lanaudit", ConsentLogFile), nil
}
