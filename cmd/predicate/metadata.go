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
	flags.StringVar(&metadataPolicyRef, "policy-ref", "", "Policy reference URL (defaults to autogov-policy-library)")
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

// parseArtifactType maps the --type flag to an ArtifactType.
func parseArtifactType(t string) (pred.ArtifactType, error) {
	switch t {
	case "image":
		return pred.ArtifactTypeContainerImage, nil
	case "blob":
		return pred.ArtifactTypeBlob, nil
	default:
		return "", fmt.Errorf("invalid type %q, must be 'image' or 'blob'", t)
	}
}

// applyGitHubContext copies GitHub context fields into opts.
func applyGitHubContext(opts *pred.Options, ctx *pred.Context) {
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
}

// parseTimestampOrNow parses an RFC3339 timestamp in UTC, falling back to now.
func parseTimestampOrNow(value string) time.Time {
	if value != "" {
		if t, err := time.Parse(time.RFC3339, value); err == nil {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}

// applyTimestamps sets the time-related fields on opts from the GitHub context.
func applyTimestamps(opts *pred.Options, ctx *pred.Context) {
	opts.StartedAt = parseTimestampOrNow(ctx.Event.WorkflowRun.CreatedAt)
	opts.CompletedAt = time.Now().UTC()
	opts.Timestamp = parseTimestampOrNow(ctx.Event.HeadCommit.Timestamp)
	if opts.Created.IsZero() {
		opts.Created = time.Now().UTC()
	}
}

// resolvePolicyRef returns the policy ref from the flag, env var, or default.
func resolvePolicyRef(flagRef string) string {
	if flagRef != "" {
		return flagRef
	}
	if envPolicyRef := os.Getenv("POLICY_REF"); envPolicyRef != "" {
		return envPolicyRef
	}
	return "https://github.com/liatrio/autogov-policy-library"
}

// applyVersion sets opts.Version from the SHA and run number when both are present.
func applyVersion(opts *pred.Options) {
	if opts.SHA != "" && opts.RunNumber != "" {
		shortSHA := opts.SHA
		if len(shortSHA) > 7 {
			shortSHA = shortSHA[:7]
		}
		opts.Version = fmt.Sprintf("%s-%s", shortSHA, opts.RunNumber)
	}
}

// applyControlIds sets the control ids derived from the owner when present.
func applyControlIds(opts *pred.Options) {
	if opts.Owner != "" {
		opts.ControlIds = []string{
			opts.Owner + "-PROVENANCE-001",
			opts.Owner + "-SBOM-002",
			opts.Owner + "-METADATA-003",
		}
	}
}

// enrichImageSubject validates and enriches the subject for container image type.
func enrichImageSubject(opts *pred.Options) error {
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
	return nil
}

// enrichBlobSubject validates and enriches the subject for blob type.
func enrichBlobSubject(opts *pred.Options) error {
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
	return nil
}

// enrichSubject runs type-specific validation and enrichment.
func enrichSubject(opts *pred.Options) error {
	switch opts.Type {
	case pred.ArtifactTypeContainerImage:
		return enrichImageSubject(opts)
	case pred.ArtifactTypeBlob:
		return enrichBlobSubject(opts)
	}
	return nil
}

func runMetadata(_ *cobra.Command, _ []string) error {
	var opts pred.Options

	// set artifact type
	artifactType, err := parseArtifactType(metadataType)
	if err != nil {
		return err
	}
	opts.Type = artifactType

	// load github context
	ctx, err := pred.LoadGitHubContext()
	if err != nil {
		return fmt.Errorf("failed to load GitHub context: %w", err)
	}

	// set github context fields
	applyGitHubContext(&opts, ctx)

	// set subject fields from flags
	opts.SubjectPath = metadataSubjectPath
	opts.FullName = metadataSubjectName
	opts.Digest = metadataSubjectDigest

	// set time-related fields
	applyTimestamps(&opts, ctx)

	// set version from sha and run number
	applyVersion(&opts)

	// set policy ref
	opts.PolicyRef = resolvePolicyRef(metadataPolicyRef)

	// set control ids
	applyControlIds(&opts)

	// set permissions
	opts.Permissions = getWorkflowPermissions(opts.Type)

	// type-specific validation and enrichment
	if err := enrichSubject(&opts); err != nil {
		return err
	}

	return pred.GenerateMetadata(opts, metadataOutput)
}
