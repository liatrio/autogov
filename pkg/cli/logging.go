package cli

import (
	"fmt"
)

// message if not in quiet mode
func LogInfo(quiet bool, format string, args ...interface{}) {
	if !quiet {
		fmt.Printf(format, args...)
	}
}

// newline if not in quiet mode
func LogInfoln(quiet bool, format string, args ...interface{}) {
	if !quiet {
		fmt.Printf(format+"\n", args...)
	}
}

// success msg if not in quiet mode
func LogSuccess(quiet bool, format string, args ...interface{}) {
	if !quiet {
		fmt.Printf("✓ "+format, args...)
	}
}

// success msg with newline if not in quiet mode
func LogSuccessln(quiet bool, format string, args ...interface{}) {
	if !quiet {
		fmt.Printf("✓ "+format+"\n", args...)
	}
}

// warning msg (always shown, even in quiet mode)
func LogWarning(format string, args ...interface{}) {
	fmt.Printf("Warning: "+format, args...)
}

// warning msg with newline (always shown, even in quiet mode)
func LogWarningln(format string, args ...interface{}) {
	fmt.Printf("Warning: "+format+"\n", args...)
}

// error msg (always shown, even in quiet mode)
func LogError(format string, args ...interface{}) {
	fmt.Printf("Error: "+format, args...)
}

// error msg with newline (always shown, even in quiet mode)
func LogErrorln(format string, args ...interface{}) {
	fmt.Printf("Error: "+format+"\n", args...)
}
