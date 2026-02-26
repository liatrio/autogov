package mutate

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func init() {
	RegisterMutator("exec", &execMutator{})
}

// execMutator runs an external command that modifies a file on disk.
// The field specifies the command template, with ${version} substituted.
// The path specifies the file the command is expected to modify.
type execMutator struct{}

// versionPattern validates version strings to prevent shell injection
var versionPattern = regexp.MustCompile(`^\d+\.\d+\.\d+(-[\w.]+)?(\+[\w.]+)?$`)

const execTimeout = 60 * time.Second

func (m *execMutator) Apply(content []byte, field string, newValue string, rule MutationRule) ([]byte, *MutationResult, error) {
	if rule.RepoRoot == "" {
		return nil, nil, fmt.Errorf("exec mutator requires repo root context")
	}

	// validate version string to prevent shell injection
	if !versionPattern.MatchString(newValue) {
		return nil, nil, fmt.Errorf("exec mutator: version %q contains invalid characters", newValue)
	}

	// substitute ${version} in the command template
	command := strings.ReplaceAll(field, "${version}", newValue)

	filePath := filepath.Join(rule.RepoRoot, rule.Path)

	// execute the command with repo root as working directory
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	cmd.Dir = rule.RepoRoot
	cmd.Env = append(os.Environ(), "VERSION="+newValue, "COMMIT_SHA="+os.Getenv("COMMIT_SHA"))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, nil, fmt.Errorf("exec command failed: %w\noutput: %s", err, string(output))
	}

	// read the file back after the command modified it
	newFileContent, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read file %s after exec: %w", rule.Path, err)
	}

	result := &MutationResult{
		Rule:     rule,
		OldValue: summarizeContent(string(content)),
		NewValue: summarizeContent(string(newFileContent)),
		Applied:  true,
		Diff:     fmt.Sprintf("exec: %s (exit 0, %d bytes output)", command, len(output)),
	}

	return newFileContent, result, nil
}

// summarizeContent returns a truncated summary for display purposes
func summarizeContent(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 80 {
		return s
	}
	return s[:77] + "..."
}
