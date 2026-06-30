package verify

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// newPolicyFlagsCmd registers the policy-related flags exactly as the
// attestation command does, for unit-testing the require-VSA guard.
func newPolicyFlagsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "attestation"}
	cmd.Flags().String(flagPolicyBundlePath, "", "")
	cmd.Flags().String(flagPolicySchemasPath, "", "")
	cmd.Flags().String(flagPolicyDataPath, "", "")
	cmd.Flags().String(flagPolicyBundleDigest, "", "")
	cmd.Flags().Bool(flagFailOnPolicyError, false, "")
	cmd.Flags().String(flagPolicyURI, "", "")
	cmd.Flags().Bool(flagGenerateVSA, false, "")
	return cmd
}

// resetPolicyViper clears viper overrides for the policy options so a subtest
// starts from a clean effective state. viper is process-global and the guard
// now reads it for env-backed options, so leakage from other tests would
// otherwise cross-contaminate. Cleaned up again after the subtest.
func resetPolicyViper(t *testing.T) {
	t.Helper()
	clear := func() {
		for _, k := range []string{flagPolicyBundlePath, flagPolicySchemasPath, flagPolicyDataPath, flagPolicyBundleDigest, flagPolicyURI} {
			viper.Set(k, "")
		}
		viper.Set(flagFailOnPolicyError, false)
	}
	clear()
	t.Cleanup(clear)
}

// TestValidatePolicyFlagsRequireVSA locks the fail-open fix: policy/gating flags
// are only honored during VSA generation, so passing them without --generate-vsa
// must fail closed instead of silently skipping policy evaluation.
func TestValidatePolicyFlagsRequireVSA(t *testing.T) {
	cases := []struct {
		name    string
		set     map[string]string
		wantErr bool
	}{
		{"policy-bundle-path without --generate-vsa fails closed", map[string]string{flagPolicyBundlePath: "ghrel://o/r"}, true},
		{"fail-on-policy-error without --generate-vsa fails closed", map[string]string{flagFailOnPolicyError: "true"}, true},
		{"policy-uri without --generate-vsa fails closed", map[string]string{flagPolicyURI: "policy-id"}, true},
		{"policy-data-path without --generate-vsa fails closed", map[string]string{flagPolicyDataPath: "data.json"}, true},
		{"policy flags WITH --generate-vsa allowed", map[string]string{flagPolicyBundlePath: "ghrel://o/r", flagGenerateVSA: "true"}, false},
		{"no policy flags allowed", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetPolicyViper(t)
			cmd := newPolicyFlagsCmd()
			for k, v := range tc.set {
				if err := cmd.Flags().Set(k, v); err != nil {
					t.Fatalf("set --%s=%s: %v", k, v, err)
				}
			}
			err := validatePolicyFlagsRequireVSA(cmd)
			switch {
			case tc.wantErr && err == nil:
				t.Fatal("expected fail-closed error, got nil")
			case !tc.wantErr && err != nil:
				t.Fatalf("expected nil, got %v", err)
			case tc.wantErr && !strings.Contains(err.Error(), flagGenerateVSA):
				t.Errorf("error should reference --%s; got %v", flagGenerateVSA, err)
			}
		})
	}
}

// TestValidatePolicyFlagsRequireVSA_EnvBacked locks the env-path half of the
// fix: policy options set via their env vars (resolved into viper) must also
// fail closed without --generate-vsa — Flags().Changed() alone misses them.
func TestValidatePolicyFlagsRequireVSA_EnvBacked(t *testing.T) {
	t.Run("env-backed policy-bundle-path fails closed", func(t *testing.T) {
		resetPolicyViper(t)
		viper.Set(flagPolicyBundlePath, "ghrel://o/r")
		if err := validatePolicyFlagsRequireVSA(newPolicyFlagsCmd()); err == nil {
			t.Fatal("env-backed --policy-bundle-path must fail closed without --generate-vsa")
		}
	})

	t.Run("env-backed fail-on-policy-error fails closed", func(t *testing.T) {
		resetPolicyViper(t)
		viper.Set(flagFailOnPolicyError, true)
		if err := validatePolicyFlagsRequireVSA(newPolicyFlagsCmd()); err == nil {
			t.Fatal("env-backed --fail-on-policy-error must fail closed without --generate-vsa")
		}
	})

	t.Run("env-backed policy flags WITH --generate-vsa allowed", func(t *testing.T) {
		resetPolicyViper(t)
		viper.Set(flagPolicyBundlePath, "ghrel://o/r")
		cmd := newPolicyFlagsCmd()
		if err := cmd.Flags().Set(flagGenerateVSA, "true"); err != nil {
			t.Fatal(err)
		}
		if err := validatePolicyFlagsRequireVSA(cmd); err != nil {
			t.Fatalf("env-backed policy flags WITH --generate-vsa should be allowed, got %v", err)
		}
	})
}

// TestVerifyUnknownSubcommandFailsClosed locks the fail-open fix: a typo'd verify
// subcommand must return a non-zero error (not print help and exit 0), so a CI
// step can't silently "pass". A bare `verify` still shows help cleanly, and a
// valid subcommand still resolves.
func TestVerifyUnknownSubcommandFailsClosed(t *testing.T) {
	newRoot := func() *cobra.Command {
		root := &cobra.Command{Use: "autogov", SilenceErrors: true, SilenceUsage: true}
		root.AddCommand(NewVerifyCmdForTesting())
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		return root
	}

	t.Run("unknown subcommand returns error", func(t *testing.T) {
		root := newRoot()
		root.SetArgs([]string{"verify", "attestaton"})
		err := root.Execute()
		if err == nil {
			t.Fatal("unknown verify subcommand must fail closed (non-nil error), got nil")
		}
		if !strings.Contains(err.Error(), "unknown command") {
			t.Errorf("expected 'unknown command' error, got %v", err)
		}
	})

	t.Run("bare verify shows help without error", func(t *testing.T) {
		root := newRoot()
		root.SetArgs([]string{"verify"})
		if err := root.Execute(); err != nil {
			t.Fatalf("bare verify should show help and exit cleanly, got %v", err)
		}
	})

	t.Run("valid subcommand resolves", func(t *testing.T) {
		root := newRoot()
		root.SetArgs([]string{"verify", "attestation", "--help"})
		if err := root.Execute(); err != nil {
			t.Fatalf("valid 'verify attestation --help' should resolve, got %v", err)
		}
	})
}
