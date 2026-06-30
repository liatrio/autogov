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

// resetPolicyViper fully clears the global viper singleton so a subtest starts
// from a clean state and leaves none behind. viper is process-global and the
// guard reads it for env-backed options; viper.Set overrides outrank BindEnv, so
// clearing individual keys with viper.Set("") would leave empty overrides that
// shadow env-backed reads in later tests. viper.Reset() is the supported reset.
func resetPolicyViper(t *testing.T) {
	t.Helper()
	viper.Reset()
	t.Cleanup(viper.Reset)
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
// fix: policy options set via their env vars must also fail closed without
// --generate-vsa — Flags().Changed() alone misses them. These exercise the real
// BindEnv + env flow (mirroring initConfig), not a viper.Set override, so they
// cover the path validatePolicyFlagsRequireVSA actually relies on in production.
func TestValidatePolicyFlagsRequireVSA_EnvBacked(t *testing.T) {
	// env-bound string options (see initConfig BindEnv): set purely via env.
	stringEnv := []struct{ flag, env, val string }{
		{flagPolicyBundlePath, "POLICY_BUNDLE_PATH", "ghrel://o/r"},
		{flagPolicySchemasPath, "POLICY_SCHEMAS_PATH", "ghrel://o/r?asset=schemas.tar.gz"},
		{flagPolicyDataPath, "POLICY_DATA_PATH", "data.json"},
	}
	for _, tc := range stringEnv {
		t.Run("env "+tc.env+" fails closed", func(t *testing.T) {
			resetPolicyViper(t)
			if err := viper.BindEnv(tc.flag, tc.env); err != nil {
				t.Fatalf("BindEnv %s: %v", tc.env, err)
			}
			t.Setenv(tc.env, tc.val)
			if err := validatePolicyFlagsRequireVSA(newPolicyFlagsCmd()); err == nil {
				t.Fatalf("env %s must fail closed without --generate-vsa", tc.env)
			}
		})
	}

	t.Run("env FAIL_ON_POLICY_ERROR fails closed", func(t *testing.T) {
		resetPolicyViper(t)
		if err := viper.BindEnv(flagFailOnPolicyError, "FAIL_ON_POLICY_ERROR"); err != nil {
			t.Fatalf("BindEnv: %v", err)
		}
		t.Setenv("FAIL_ON_POLICY_ERROR", "true")
		if err := validatePolicyFlagsRequireVSA(newPolicyFlagsCmd()); err == nil {
			t.Fatal("env FAIL_ON_POLICY_ERROR must fail closed without --generate-vsa")
		}
	})

	t.Run("env-backed policy flag WITH --generate-vsa allowed", func(t *testing.T) {
		resetPolicyViper(t)
		if err := viper.BindEnv(flagPolicyBundlePath, "POLICY_BUNDLE_PATH"); err != nil {
			t.Fatalf("BindEnv: %v", err)
		}
		t.Setenv("POLICY_BUNDLE_PATH", "ghrel://o/r")
		cmd := newPolicyFlagsCmd()
		if err := cmd.Flags().Set(flagGenerateVSA, "true"); err != nil {
			t.Fatal(err)
		}
		if err := validatePolicyFlagsRequireVSA(cmd); err != nil {
			t.Fatalf("env-backed policy flag WITH --generate-vsa should be allowed, got %v", err)
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
