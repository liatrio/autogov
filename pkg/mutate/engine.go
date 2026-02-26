package mutate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ApplyMutations executes all mutation rules against files in repoRoot
// if dryRun is true, computes results without writing to disk
func ApplyMutations(repoRoot string, config *MutationConfig, version string, dryRun bool) ([]MutationResult, error) {
	var results []MutationResult

	for _, rule := range config.Rules {
		result := applyRule(repoRoot, rule, version, dryRun)
		results = append(results, result)
	}

	return results, nil
}

// DryRunMutations is a convenience wrapper for ApplyMutations with dryRun=true
func DryRunMutations(repoRoot string, config *MutationConfig, version string) ([]MutationResult, error) {
	return ApplyMutations(repoRoot, config, version, true)
}

// applyRule processes a single mutation rule
func applyRule(repoRoot string, rule MutationRule, version string, dryRun bool) MutationResult {
	mutator, err := GetMutator(rule.Type)
	if err != nil {
		return MutationResult{Rule: rule, Error: err.Error()}
	}

	filePath := filepath.Join(repoRoot, rule.Path)

	// validate path stays within repo root
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return MutationResult{Rule: rule, Error: fmt.Sprintf("invalid path: %v", err)}
	}
	absRoot, err := filepath.Abs(repoRoot)
	if err != nil {
		return MutationResult{Rule: rule, Error: fmt.Sprintf("invalid repo root: %v", err)}
	}
	if !strings.HasPrefix(absPath, absRoot+string(filepath.Separator)) && absPath != absRoot {
		return MutationResult{Rule: rule, Error: "path escapes repository root"}
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return MutationResult{Rule: rule, Error: fmt.Sprintf("failed to read file: %v", err)}
	}

	// exec mutations cannot be simulated in dry-run mode
	if rule.Type == "exec" && dryRun {
		return MutationResult{
			Rule:    rule,
			Applied: false,
			Diff:    "exec mutations are not simulated in dry-run mode",
		}
	}

	// set repo root for mutators that need filesystem context (e.g., exec)
	rule.RepoRoot = repoRoot

	// for structured mutators (json/yaml/toml), newValue is the version string
	// for regex, the Replace template handles substitution
	newValue := version

	updated, result, err := mutator.Apply(content, rule.Field, newValue, rule)
	if err != nil {
		return MutationResult{Rule: rule, Error: err.Error()}
	}

	if !dryRun {
		if err := atomicWrite(filePath, updated); err != nil {
			result.Error = fmt.Sprintf("failed to write file: %v", err)
			result.Applied = false
		}
	} else {
		result.Applied = false
		result.Diff = computeDiff(string(content), string(updated), rule.Path)
	}

	return *result
}

// atomicWrite writes data to a temp file then renames to the target path
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".mutate-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	// get original file permissions
	info, err := os.Stat(path)
	if err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to stat original file: %w", err)
	}

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	if err := os.Chmod(tmpPath, info.Mode()); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// computeDiff generates a simple before/after diff summary
func computeDiff(before, after, path string) string {
	if before == after {
		return "no changes"
	}

	beforeLines := strings.Split(before, "\n")
	afterLines := strings.Split(after, "\n")

	var diff strings.Builder
	diff.WriteString(fmt.Sprintf("--- %s\n+++ %s\n", path, path))

	// simple line-by-line diff (find first difference)
	maxLines := len(beforeLines)
	if len(afterLines) > maxLines {
		maxLines = len(afterLines)
	}

	for i := 0; i < maxLines; i++ {
		var bLine, aLine string
		if i < len(beforeLines) {
			bLine = beforeLines[i]
		}
		if i < len(afterLines) {
			aLine = afterLines[i]
		}
		if bLine != aLine {
			if bLine != "" {
				diff.WriteString(fmt.Sprintf("-%s\n", bLine))
			}
			if aLine != "" {
				diff.WriteString(fmt.Sprintf("+%s\n", aLine))
			}
		}
	}

	return diff.String()
}
