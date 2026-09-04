package evidence

import (
	"fmt"
	"os"
	"path/filepath"
)

// writeOutput duplicates the small file/stdout adapter so the companion does
// not depend on AutoGov's predicate authoring package.
func writeOutput(output []byte, outputFile string) error {
	if outputFile == "" {
		if _, err := os.Stdout.Write(output); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
		return nil
	}

	temporary, err := os.CreateTemp(filepath.Dir(outputFile), "."+filepath.Base(outputFile)+".tmp-")
	if err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()

	if _, err := temporary.Write(output); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("failed to write output file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}
	if err := os.Rename(temporaryPath, outputFile); err != nil {
		return fmt.Errorf("failed to commit output file: %w", err)
	}
	committed = true
	return nil
}
