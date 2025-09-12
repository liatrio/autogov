package cli

// flags common across all commands
type CommonOptions struct {
	Quiet        bool
	CertIdentity string
	CertIssuer   string
	SourceRef    string
}

// handles artifact selection (blob paths, image digest, repo, positional)
type ArtifactSelector struct {
	BlobPaths        []string // expanded blob paths
	ImageDigest      string   // image digest (bare or full ref)
	Repo             string   // repository (owner/repo format)
	PositionalDigest string   // digest provided as positional argument
	FullImageRef     string   // constructed full image reference if needed
}

// flags specific to offline verification
type OfflineOptions struct {
	AttestationsPath  string
	TrustedRoot       string
	GenerateVSA       bool
	VSAOutput         string
	PolicyURI         string
	PolicyBundlePath  string
	PolicySchemasPath string
}

// flags specific to download command
type DownloadOptions struct {
	Output string
	Format string
}
