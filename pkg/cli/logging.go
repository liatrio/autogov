package cli

import (
	"fmt"
)

// info message with newline if not in quiet mode
func LogInfoln(quiet bool, format string, args ...interface{}) {
	if !quiet {
		fmt.Printf(format+"\n", args...)
	}
}

// success message with newline if not in quiet mode
func LogSuccessln(quiet bool, format string, args ...interface{}) {
	if !quiet {
		fmt.Printf("✓ "+format+"\n", args...)
	}
}
