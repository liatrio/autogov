package predicate

import (
	"encoding/json"
	"strings"
	"time"
)

// ArtifactType represents the type of artifact being attested.
type ArtifactType string

const (
	ArtifactTypeBlob           ArtifactType = "blob"
	ArtifactTypeContainerImage ArtifactType = "container-image"

	// MetadataPredicateTypeURI is the custom autogov predicate type for metadata attestations.
	MetadataPredicateTypeURI = "https://autogov.dev/attestation/metadata/v1"

	// DepscanPredicateTypeURI is the in-toto vulnerability predicate type.
	DepscanPredicateTypeURI = "https://in-toto.io/attestation/vulns/v0.2"
)

// Metadata represents the predicate portion of a metadata attestation.
type Metadata struct {
	Artifact struct {
		Version  string `json:"version"`
		Created  string `json:"created"`
		Type     string `json:"type"`
		Registry string `json:"registry,omitempty"`
		FullName string `json:"fullName,omitempty"`
		Digest   string `json:"digest,omitempty"`
		Path     string `json:"path,omitempty"`
	} `json:"artifact"`
	RepositoryData struct {
		Repository      string `json:"repository"`
		RepositoryID    string `json:"repositoryId"`
		GitHubServerURL string `json:"githubServerURL"`
	} `json:"repositoryData"`
	OwnerData struct {
		Owner   string `json:"owner"`
		OwnerID string `json:"ownerId"`
	} `json:"ownerData"`
	RunnerData struct {
		OS          string `json:"os"`
		Arch        string `json:"arch"`
		Environment string `json:"environment"`
	} `json:"runnerData"`
	WorkflowData struct {
		WorkflowRefPath string         `json:"workflowRefPath"`
		Inputs          map[string]any `json:"inputs,omitempty"`
		Branch          string         `json:"branch"`
		Event           string         `json:"event"`
	} `json:"workflowData"`
	JobData struct {
		RunNumber   string `json:"runNumber"`
		RunID       string `json:"runId"`
		Status      string `json:"status"`
		TriggeredBy string `json:"triggeredBy"`
		StartedAt   string `json:"startedAt"`
		CompletedAt string `json:"completedAt"`
	} `json:"jobData"`
	CommitData struct {
		SHA       string `json:"sha"`
		Timestamp string `json:"timestamp"`
	} `json:"commitData"`
	Organization struct {
		Name string `json:"name"`
	} `json:"organization"`
	Compliance struct {
		PolicyRef  string   `json:"policyRef"`
		ControlIds []string `json:"controlIds"`
	} `json:"compliance"`
	Security struct {
		Permissions map[string]string `json:"permissions"`
	} `json:"security"`
}

// Options contains all fields needed to generate a metadata predicate.
type Options struct {
	// artifact fields
	Version     string
	Created     time.Time
	Type        ArtifactType
	Registry    string
	FullName    string
	SubjectPath string
	Digest      string

	// repo fields
	Repository      string
	RepositoryID    string
	GitHubServerURL string

	// owner fields
	Owner   string
	OwnerID string

	// runner fields
	OS          string
	Arch        string
	Environment string

	// workflow fields
	WorkflowRefPath string
	Inputs          map[string]any
	Branch          string
	Event           string

	// job fields
	RunNumber   string
	RunID       string
	Status      string
	TriggeredBy string
	StartedAt   time.Time
	CompletedAt time.Time

	// commit fields
	SHA       string
	Timestamp time.Time

	// org fields
	OrgName string

	// compliance fields
	PolicyRef  string
	ControlIds []string

	// permissions fields
	Permissions map[string]string
}

// NewFromOptions creates a new Metadata from the given options.
func NewFromOptions(opts Options) *Metadata {
	m := &Metadata{}

	m.Artifact.Version = opts.Version
	m.Artifact.Created = opts.Created.Format(time.RFC3339)
	m.Artifact.Type = string(opts.Type)

	switch opts.Type {
	case ArtifactTypeContainerImage:
		m.Artifact.Registry = opts.Registry
		m.Artifact.FullName = opts.FullName
		m.Artifact.Digest = opts.Digest
	case ArtifactTypeBlob:
		m.Artifact.Path = opts.SubjectPath
	}

	m.RepositoryData.Repository = opts.Repository
	m.RepositoryData.RepositoryID = opts.RepositoryID
	m.RepositoryData.GitHubServerURL = opts.GitHubServerURL

	m.OwnerData.Owner = opts.Owner
	m.OwnerData.OwnerID = opts.OwnerID

	m.RunnerData.OS = opts.OS
	m.RunnerData.Arch = opts.Arch
	m.RunnerData.Environment = opts.Environment

	m.WorkflowData.WorkflowRefPath = opts.WorkflowRefPath
	m.WorkflowData.Branch = opts.Branch
	m.WorkflowData.Event = opts.Event

	m.JobData.RunNumber = opts.RunNumber
	m.JobData.RunID = opts.RunID
	m.JobData.Status = opts.Status
	m.JobData.TriggeredBy = opts.TriggeredBy
	m.JobData.StartedAt = opts.StartedAt.Format(time.RFC3339)
	m.JobData.CompletedAt = opts.CompletedAt.Format(time.RFC3339)

	m.CommitData.SHA = opts.SHA
	m.CommitData.Timestamp = opts.Timestamp.Format(time.RFC3339)

	m.Organization.Name = opts.OrgName

	m.Compliance.PolicyRef = opts.PolicyRef
	m.Compliance.ControlIds = opts.ControlIds

	m.Security.Permissions = opts.Permissions

	if opts.Inputs != nil {
		m.WorkflowData.Inputs = opts.Inputs
	} else {
		m.WorkflowData.Inputs = make(map[string]any)
	}

	return m
}

// ensureSHA256Prefix adds sha256: prefix if missing.
func ensureSHA256Prefix(digest string) string {
	if !strings.HasPrefix(digest, "sha256:") {
		return "sha256:" + digest
	}
	return digest
}

// Generate produces the JSON representation of the metadata predicate.
func (m *Metadata) Generate() ([]byte, error) {
	if m.Artifact.Type == string(ArtifactTypeContainerImage) {
		m.Artifact.Digest = ensureSHA256Prefix(m.Artifact.Digest)
	}
	return json.MarshalIndent(m, "", "  ")
}

// DependencyScan represents the predicate portion of a dependency scan attestation.
type DependencyScan struct {
	Type        ArtifactType `json:"-"`
	SubjectName string       `json:"-"`
	SubjectPath string       `json:"-"`
	Digest      string       `json:"-"`
	Scanner     struct {
		Name    string `json:"name"`
		URI     string `json:"uri"`
		Version string `json:"version"`
		DB      struct {
			URI        string `json:"uri"`
			Version    string `json:"version,omitempty"`
			LastUpdate string `json:"lastUpdate,omitempty"`
		} `json:"db"`
		Result []ScanResult `json:"result"`
	} `json:"scanner"`
	Metadata struct {
		ScanStartedOn  string `json:"scanStartedOn"`
		ScanFinishedOn string `json:"scanFinishedOn"`
	} `json:"metadata,omitempty"`
}

// Generate produces the JSON representation of the dependency scan predicate.
func (s *DependencyScan) Generate() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

// DependencyScanOptions contains options for creating a new dependency scan.
type DependencyScanOptions struct {
	Type        ArtifactType
	SubjectName string
	SubjectPath string
	Digest      string
	ResultsPath string
	StartedAt   time.Time
	FinishedAt  time.Time
}

// GrypeResult represents Grype scan results.
type GrypeResult struct {
	Descriptor struct {
		Version   string `json:"version"`
		Timestamp string `json:"timestamp"`
		DB        struct {
			Status *struct {
				Built         string `json:"built"`
				SchemaVersion string `json:"schemaVersion"`
				From          string `json:"from,omitempty"`
			} `json:"status,omitempty"`
		} `json:"db"`
	} `json:"descriptor"`
	Matches []struct {
		Vulnerability struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			CVSS     []struct {
				Metrics struct {
					BaseScore float64 `json:"baseScore"`
				} `json:"metrics"`
			} `json:"cvss"`
		} `json:"vulnerability"`
	} `json:"matches"`
}

// ScanResult represents a single vulnerability finding.
type ScanResult struct {
	ID       string     `json:"id"`
	Severity []Severity `json:"severity"`
}

// Severity represents a vulnerability severity score.
type Severity struct {
	Method string `json:"method"`
	Score  string `json:"score"`
}

// NewDependencyScan creates a new DependencyScan from options.
func NewDependencyScan(opts DependencyScanOptions) *DependencyScan {
	scan := &DependencyScan{
		Type:        opts.Type,
		SubjectName: opts.SubjectName,
		SubjectPath: opts.SubjectPath,
		Digest:      opts.Digest,
	}

	scan.Scanner.Result = make([]ScanResult, 0)

	scan.Metadata.ScanStartedOn = opts.StartedAt.Format("2006-01-02T15:04:05Z")
	scan.Metadata.ScanFinishedOn = opts.FinishedAt.Format("2006-01-02T15:04:05Z")

	return scan
}
