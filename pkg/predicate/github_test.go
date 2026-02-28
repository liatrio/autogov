package predicate

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadGitHubContext(t *testing.T) {
	t.Run("valid_environment", func(t *testing.T) {
		t.Setenv("RUNNER_OS", "Linux")
		t.Setenv("RUNNER_ARCH", "X64")
		t.Setenv("GITHUB_WORKFLOW_INPUTS", `{"key":"value"}`)

		ctx, err := LoadGitHubContext()
		assert.NoError(t, err)
		assert.Equal(t, "value", ctx.Inputs["key"])
	})

	t.Run("workflow_inputs_from_json", func(t *testing.T) {
		t.Setenv("RUNNER_OS", "Linux")
		t.Setenv("RUNNER_ARCH", "X64")
		t.Setenv("GITHUB_WORKFLOW_INPUTS", `{"key":"value","extra-key":"extra-value"}`)

		ctx, err := LoadGitHubContext()
		assert.NoError(t, err)
		assert.Equal(t, "value", ctx.Inputs["key"])
		assert.Equal(t, "extra-value", ctx.Inputs["extra-key"])
	})

	t.Run("missing_runner_os", func(t *testing.T) {
		os.Unsetenv("RUNNER_OS")
		t.Setenv("RUNNER_ARCH", "X64")

		_, err := LoadGitHubContext()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "RUNNER_OS environment variable not set")
	})

	t.Run("missing_runner_arch", func(t *testing.T) {
		t.Setenv("RUNNER_OS", "Linux")
		os.Unsetenv("RUNNER_ARCH")

		_, err := LoadGitHubContext()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "RUNNER_ARCH environment variable not set")
	})

	t.Run("default_job_status", func(t *testing.T) {
		t.Setenv("RUNNER_OS", "Linux")
		t.Setenv("RUNNER_ARCH", "X64")
		os.Unsetenv("GITHUB_JOB_STATUS")

		ctx, err := LoadGitHubContext()
		assert.NoError(t, err)
		assert.Equal(t, "success", ctx.JobStatus)
	})
}
