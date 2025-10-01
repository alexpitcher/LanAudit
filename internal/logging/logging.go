package logging

import (
	"fmt"
	"log"
	"os"
	"sync"
)

var (
	logger *log.Logger
	once   sync.Once
)

func initLogger() {
	file, err := os.OpenFile("log.txt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("logging: failed to open log file, using stderr: %v", err)
		logger = log.New(os.Stderr, "lanaudit ", log.LstdFlags|log.Lmicroseconds)
		return
	}
	logger = log.New(file, "", log.LstdFlags|log.Lmicroseconds)
}

func ensureLogger() {
	once.Do(initLogger)
}

func logf(level, format string, args ...interface{}) {
	ensureLogger()
	if logger == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	logger.Printf("[%s] %s", level, msg)
}

// Infof logs an informational message.
func Infof(format string, args ...interface{}) {
	logf("INFO", format, args...)
}

// Warnf logs a warning message.
func Warnf(format string, args ...interface{}) {
	logf("WARN", format, args...)
}

// Errorf logs an error message.
func Errorf(format string, args ...interface{}) {
	logf("ERROR", format, args...)
}

// Debugf logs a debug message.
func Debugf(format string, args ...interface{}) {
	logf("DEBUG", format, args...)
}
