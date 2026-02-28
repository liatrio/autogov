package cmd

import (
	"fmt"
	"log"

	"github.com/liatrio/autogov/cmd/predicate"
	"github.com/liatrio/autogov/cmd/release"
	"github.com/liatrio/autogov/cmd/verify"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// build-time variables set via ldflags
	Version    = "dev"
	Commit     = "none"
	Date       = "unknown"
	OpaVersion = "v1.8.0"
)

var rootCmd = &cobra.Command{
	Use:   "autogov",
	Short: "Attestation verification and release management",
	Long: `autogov is a unified CLI for attestation verification and release management.

It provides commands for:
  - Verifying GitHub artifact attestations using Sigstore
  - Managing software releases with attestation support
  - Generating changelogs from conventional commits

Use 'autogov verify' for attestation verification.`,
	SilenceErrors: true,
	SilenceUsage:  true,
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// propagate build-time version info to verify package for VSA generation
	verify.SetBuildInfo(Version, OpaVersion)

	// add subcommands
	rootCmd.AddCommand(verify.VerifyCmd)
	rootCmd.AddCommand(downloadCmd)
	rootCmd.AddCommand(offlineCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(release.ReleaseCmd)
	rootCmd.AddCommand(predicate.PredicateCmd)
	rootCmd.AddCommand(changelogCmd)

	// set opa version in viper for policy package to use
	viper.Set("opa-version", OpaVersion)
}

func initConfig() {
	// bind environment variables
	envBinds := map[string]string{
		"image-digest":         "IMAGE_DIGEST",
		"blob-path":            "BLOB_PATH",
		"repo":                 "REPO",
		"cert-identity":        "CERT_IDENTITY",
		"cert-issuer":          "CERT_ISSUER",
		"quiet":                "QUIET",
		"source-ref":           "SOURCE_REF",
		"attestations-path":    "ATTESTATIONS_PATH",
		"cert-identity-list":   "CERT_IDENTITY_LIST",
		"no-cache":             "NO_CACHE",
		"policy-bundle-path":   "POLICY_BUNDLE_PATH",
		"policy-schemas-path":  "POLICY_SCHEMAS_PATH",
		"policy-data-path":     "POLICY_DATA_PATH",
		"fail-on-policy-error": "FAIL_ON_POLICY_ERROR",
		"trusted-root-source":  "TRUSTED_ROOT_SOURCE",
	}

	for key, env := range envBinds {
		if err := viper.BindEnv(key, env); err != nil {
			panic(fmt.Sprintf("failed to bind environment variables: %v", err))
		}
	}
}

// GetRootCmd returns the root command for testing
func GetRootCmd() *cobra.Command {
	return rootCmd
}
