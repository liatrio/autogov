package predicate

import (
	"fmt"
	"os"
)

// environment variable names
const (
	// github
	EnvGitHubRepository      = "GITHUB_REPOSITORY"
	EnvGitHubRepositoryID    = "GITHUB_REPOSITORY_ID"
	EnvGitHubRepositoryOwner = "GITHUB_REPOSITORY_OWNER"
	EnvGitHubOwnerID         = "GITHUB_REPOSITORY_OWNER_ID"
	EnvGitHubServerURL       = "GITHUB_SERVER_URL"
	EnvGitHubSHA             = "GITHUB_SHA"
	EnvGitHubRefName         = "GITHUB_REF_NAME"
	EnvGitHubEventName       = "GITHUB_EVENT_NAME"
	EnvGitHubActor           = "GITHUB_ACTOR"
	EnvGitHubRunID           = "GITHUB_RUN_ID"
	EnvGitHubRunNumber       = "GITHUB_RUN_NUMBER"
	EnvGitHubWorkflowRef     = "GITHUB_WORKFLOW_REF"
	EnvGitHubEventPath       = "GITHUB_EVENT_PATH"
	EnvGitHubWorkflowInputs  = "GITHUB_WORKFLOW_INPUTS"
	EnvGitHubJobStatus       = "GITHUB_JOB_STATUS"

	// runner
	EnvRunnerOS          = "RUNNER_OS"
	EnvRunnerArch        = "RUNNER_ARCH"
	EnvRunnerEnvironment = "RUNNER_ENVIRONMENT"

	// tokens
	//nolint:gosec // These are environment variable names, not credentials
	EnvGitHubToken = "GITHUB_TOKEN"
	//nolint:gosec // These are environment variable names, not credentials
	EnvGHToken = "GH_TOKEN"

	// config
	EnvPolicyRepoOwner = "POLICY_REPO_OWNER"
	EnvPolicyRepoName  = "POLICY_REPO_NAME"
	EnvPolicyVersion   = "POLICY_VERSION"
	EnvSchemasPath     = "SCHEMAS_PATH"

	// permissions
	EnvWorkflowPermissions = "WORKFLOW_PERMISSIONS"
)

// GetEnvOrDefault returns the value of the environment variable or the default value.
func GetEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// GetRequiredEnv returns the value of a required environment variable or an error.
func GetRequiredEnv(key string) (string, error) {
	if value := os.Getenv(key); value != "" {
		return value, nil
	}
	return "", fmt.Errorf("required environment variable %s is not set", key)
}

// GetGitHubToken returns the GitHub token from environment variables.
func GetGitHubToken() (string, error) {
	for _, key := range []string{EnvGHToken, EnvGitHubToken} {
		if token := os.Getenv(key); token != "" {
			return token, nil
		}
	}
	return "", fmt.Errorf("GitHub token not found (set GH_TOKEN or GITHUB_TOKEN)")
}
