package predicate

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	pred "github.com/liatrio/autogov/pkg/predicate"
	"github.com/spf13/cobra"
)

var metadataCmd = &cobra.Command{
	Use:   "metadata",
	Short: "Generate metadata attestation predicate",
	RunE:  runMetadata,
}

var (
	metadataSubjectPath   string
	metadataSubjectName   string
	metadataSubjectDigest string
	metadataOutput        string
	metadataType          string
	metadataPolicyRef     string
)

func init() {
	flags := metadataCmd.Flags()
	flags.StringVar(&metadataSubjectPath, "subject-path", "", "Path to the subject file (required for blob type)")
	flags.StringVar(&metadataSubjectName, "subject-name", "", "Name of the subject being attested (required for image type)")
	flags.StringVar(&metadataSubjectDigest, "subject-digest", "", "SHA256 digest of the subject (required for image type)")
	flags.StringVar(&metadataOutput, "output", "", "Output file path (defaults to stdout)")
	flags.StringVar(&metadataType, "type", "image", "Type of artifact (image or blob)")
	flags.StringVar(&metadataPolicyRef, "policy-ref", "", "Policy reference URL (defaults to demo policy library)")
}

// getWorkflowPermissions returns permissions from WORKFLOW_PERMISSIONS env var or defaults.
func getWorkflowPermissions(artifactType pred.ArtifactType) map[string]string {
	if permsJSON := os.Getenv(pred.EnvWorkflowPermissions); permsJSON != "" {
		var perms map[string]string
		if err := json.Unmarshal([]byte(permsJSON), &perms); err == nil && len(perms) > 0 {
			return perms
		}
	}

	perms := map[string]string{
		"id-token":     "write",
		"attestations": "write",
		"contents":     "read",
	}
	if artifactType == pred.ArtifactTypeContainerImage {
		perms["packages"] = "write"
	} else {
		perms["packages"] = "none"
	}
	return perms
}

func runMetadata(_ *cobra.Command, _ []string) error {
	var opts pred.Options

	// set artifact type
	switch metadataType {
	case "image":
		opts.Type = pred.ArtifactTypeContainerImage
	case "blob":
		opts.Type = pred.ArtifactTypeBlob
	default:
		return fmt.Errorf("invalid type %q, must be 'image' or 'blob'", metadataType)
	}

	// load github context
	ctx, err := pred.LoadGitHubContext()
	if err != nil {
		return fmt.Errorf("failed to load GitHub context: %w", err)
	}

	// set github context fields
	opts.Repository = ctx.Repository
	opts.RepositoryID = ctx.RepositoryID
	opts.GitHubServerURL = ctx.ServerURL
	opts.Owner = ctx.RepositoryOwner
	opts.OwnerID = ctx.RepositoryOwnerID
	opts.OS = ctx.Runner.OS
	opts.Arch = ctx.Runner.Arch
	opts.Environment = ctx.Runner.Environment
	opts.WorkflowRefPath = ctx.WorkflowRef
	opts.Branch = ctx.RefName
	opts.Event = ctx.EventName
	opts.RunNumber = ctx.RunNumber
	opts.RunID = ctx.RunID
	opts.Status = ctx.JobStatus
	opts.TriggeredBy = ctx.Actor
	opts.SHA = ctx.SHA
	opts.OrgName = ctx.Organization.Name
	opts.Inputs = ctx.Inputs

	// set subject fields from flags
	opts.SubjectPath = metadataSubjectPath
	opts.FullName = metadataSubjectName
	opts.Digest = metadataSubjectDigest

	// parse workflow run creation time
	if ctx.Event.WorkflowRun.CreatedAt != "" {
		if startTime, err := time.Parse(time.RFC3339, ctx.Event.WorkflowRun.CreatedAt); err == nil {
			opts.StartedAt = startTime.UTC()
		} else {
			opts.StartedAt = time.Now().UTC()
		}
	} else {
		opts.StartedAt = time.Now().UTC()
	}

	// set completed time
	opts.CompletedAt = time.Now().UTC()

	// parse commit timestamp
	if ctx.Event.HeadCommit.Timestamp != "" {
		if commitTime, err := time.Parse(time.RFC3339, ctx.Event.HeadCommit.Timestamp); err == nil {
			opts.Timestamp = commitTime.UTC()
		} else {
			opts.Timestamp = time.Now().UTC()
		}
	} else {
		opts.Timestamp = time.Now().UTC()
	}

	// set version from sha and run number
	if opts.SHA != "" && opts.RunNumber != "" {
		shortSHA := opts.SHA
		if len(shortSHA) > 7 {
			shortSHA = shortSHA[:7]
		}
		opts.Version = fmt.Sprintf("%s-%s", shortSHA, opts.RunNumber)
	}

	// set created time
	if opts.Created.IsZero() {
		opts.Created = time.Now().UTC()
	}

	// set policy ref
	if metadataPolicyRef != "" {
		opts.PolicyRef = metadataPolicyRef
	} else if envPolicyRef := os.Getenv("POLICY_REF"); envPolicyRef != "" {
		opts.PolicyRef = envPolicyRef
	} else {
		opts.PolicyRef = "https://github.com/liatrio/liatrio-rego-policy-library"
	}

	// set control ids
	if opts.Owner != "" {
		opts.ControlIds = []string{
			opts.Owner + "-PROVENANCE-001",
			opts.Owner + "-SBOM-002",
			opts.Owner + "-METADATA-003",
		}
	}

	// set permissions
	opts.Permissions = getWorkflowPermissions(opts.Type)

	// type-specific validation and enrichment
	switch opts.Type {
	case pred.ArtifactTypeContainerImage:
		if opts.FullName == "" {
			return fmt.Errorf("--subject-name is required for image type")
		}
		if opts.Digest == "" {
			return fmt.Errorf("--subject-digest is required for image type")
		}
		// add sha256 to fullname if missing
		if !strings.Contains(opts.FullName, "@sha256:") {
			opts.FullName = fmt.Sprintf("%s@%s", opts.FullName, opts.Digest)
		}
		// get registry from hostname in subject-name
		if parts := strings.Split(opts.FullName, "/"); len(parts) > 2 && strings.Contains(parts[0], ".") {
			opts.Registry = parts[0]
		}
	case pred.ArtifactTypeBlob:
		if opts.SubjectPath == "" {
			return fmt.Errorf("--subject-path is required for blob type")
		}
		// calc digest for blob if not provided
		if opts.Digest == "" {
			digest, err := pred.CalculateDigest(opts.SubjectPath)
			if err != nil {
				return fmt.Errorf("failed to calculate digest: %w", err)
			}
			opts.Digest = digest
		}
	}

	return pred.GenerateMetadata(opts, metadataOutput)
}
