package predicate

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Context represents the GitHub Actions runtime context.
type Context struct {
	Repository        string `json:"repository"`
	RepositoryOwner   string `json:"repository_owner"`
	RepositoryID      string `json:"repository_id"`
	ServerURL         string `json:"server_url"`
	RepositoryOwnerID string `json:"repository_owner_id"`
	WorkflowRef       string `json:"workflow_ref"`
	RefName           string `json:"ref_name"`
	EventName         string `json:"event_name"`
	SHA               string `json:"sha"`
	RunNumber         string `json:"run_number"`
	RunID             string `json:"run_id"`
	Actor             string `json:"actor"`

	Event struct {
		WorkflowRun struct {
			CreatedAt string `json:"created_at"`
		} `json:"workflow_run"`
		HeadCommit struct {
			Timestamp string `json:"timestamp"`
		} `json:"head_commit"`
	} `json:"event"`

	Inputs    map[string]any `json:"inputs"`
	JobStatus string         `json:"job_status"`
	Runner    *Runner        `json:"runner"`

	Organization struct {
		Name string `json:"name"`
	} `json:"organization"`
}

// Runner represents GitHub Actions runner info.
type Runner struct {
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	Environment string `json:"environment"`
}

// LoadGitHubContext loads GitHub Actions context from environment variables.
func LoadGitHubContext() (*Context, error) {
	ctx := &Context{
		Repository:        os.Getenv(EnvGitHubRepository),
		RepositoryID:      os.Getenv(EnvGitHubRepositoryID),
		RepositoryOwner:   os.Getenv(EnvGitHubRepositoryOwner),
		RepositoryOwnerID: os.Getenv(EnvGitHubOwnerID),
		ServerURL:         os.Getenv(EnvGitHubServerURL),
		SHA:               os.Getenv(EnvGitHubSHA),
		RefName:           os.Getenv(EnvGitHubRefName),
		EventName:         os.Getenv(EnvGitHubEventName),
		Actor:             os.Getenv(EnvGitHubActor),
		RunID:             os.Getenv(EnvGitHubRunID),
		RunNumber:         os.Getenv(EnvGitHubRunNumber),
		WorkflowRef:       os.Getenv(EnvGitHubWorkflowRef),
		JobStatus:         os.Getenv(EnvGitHubJobStatus),
		Inputs:            make(map[string]any),
	}

	if ctx.JobStatus == "" {
		ctx.JobStatus = "success"
	}

	// get event data
	if eventData, err := os.ReadFile(os.Getenv(EnvGitHubEventPath)); err == nil {
		var event struct {
			WorkflowRun struct {
				CreatedAt string `json:"created_at"`
			} `json:"workflow_run"`
			HeadCommit struct {
				Timestamp string `json:"timestamp"`
			} `json:"head_commit"`
		}
		if err := json.Unmarshal(eventData, &event); err == nil {
			if t, err := time.Parse(time.RFC3339, event.WorkflowRun.CreatedAt); err == nil {
				ctx.Event.WorkflowRun.CreatedAt = t.UTC().Format(time.RFC3339)
			} else {
				ctx.Event.WorkflowRun.CreatedAt = time.Now().UTC().Format(time.RFC3339)
			}
			if t, err := time.Parse(time.RFC3339, event.HeadCommit.Timestamp); err == nil {
				ctx.Event.HeadCommit.Timestamp = t.UTC().Format(time.RFC3339)
			}
		}
	}

	if ctx.Event.HeadCommit.Timestamp == "" {
		ctx.Event.HeadCommit.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	// get workflow inputs
	if workflowInputs := os.Getenv(EnvGitHubWorkflowInputs); workflowInputs != "" {
		var inputs map[string]any
		if err := json.Unmarshal([]byte(workflowInputs), &inputs); err != nil {
			return nil, fmt.Errorf("failed to parse workflow inputs: %w", err)
		}
		if len(inputs) > 0 {
			ctx.Inputs = inputs
		}
	}

	osName := os.Getenv(EnvRunnerOS)
	if osName == "" {
		return nil, fmt.Errorf("RUNNER_OS environment variable not set")
	}

	arch := os.Getenv(EnvRunnerArch)
	if arch == "" {
		return nil, fmt.Errorf("RUNNER_ARCH environment variable not set")
	}

	ctx.Runner = &Runner{
		OS:          osName,
		Arch:        arch,
		Environment: os.Getenv(EnvRunnerEnvironment),
	}

	if ctx.RepositoryOwner != "" {
		ctx.Organization.Name = ctx.RepositoryOwner
	}

	return ctx, nil
}
