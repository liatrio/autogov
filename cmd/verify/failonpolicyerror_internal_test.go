package verify

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// newFailOnPolicyErrorCmd builds a minimal command with just the
// fail-on-policy-error flag registered, mirroring how the real attestation
// command registers it.
func newFailOnPolicyErrorCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().Bool(flagFailOnPolicyError, false, "")
	return cmd
}

// TestApplyFailOnPolicyError_EnvHonored locks the regression at
// attestation.go: with FAIL_ON_POLICY_ERROR=true and no --fail-on-policy-error
// flag, the env-bound viper value must survive (not be clobbered by the flag
// default false).
func TestApplyFailOnPolicyError_EnvHonored(t *testing.T) {
	defer viper.Reset()
	viper.Reset()
	if err := viper.BindEnv("fail-on-policy-error", "FAIL_ON_POLICY_ERROR"); err != nil {
		t.Fatalf("BindEnv: %v", err)
	}
	t.Setenv("FAIL_ON_POLICY_ERROR", "true")

	cmd := newFailOnPolicyErrorCmd()
	// do NOT pass --fail-on-policy-error; the env value must survive
	applyFailOnPolicyError(cmd)

	if !viper.GetBool("fail-on-policy-error") {
		t.Error("FAIL_ON_POLICY_ERROR=true was clobbered to false when the flag was absent")
	}
}

// TestApplyFailOnPolicyError_FlagOverridesEnv: an explicit
// --fail-on-policy-error=false wins over FAIL_ON_POLICY_ERROR=true.
func TestApplyFailOnPolicyError_FlagOverridesEnv(t *testing.T) {
	defer viper.Reset()
	viper.Reset()
	if err := viper.BindEnv("fail-on-policy-error", "FAIL_ON_POLICY_ERROR"); err != nil {
		t.Fatalf("BindEnv: %v", err)
	}
	t.Setenv("FAIL_ON_POLICY_ERROR", "true")

	cmd := newFailOnPolicyErrorCmd()
	if err := cmd.Flags().Set(flagFailOnPolicyError, "false"); err != nil {
		t.Fatalf("set flag: %v", err)
	}
	applyFailOnPolicyError(cmd)

	if viper.GetBool("fail-on-policy-error") {
		t.Error("explicit --fail-on-policy-error=false should override FAIL_ON_POLICY_ERROR=true")
	}
}

// TestApplyFailOnPolicyError_FlagTrueNoEnv: an explicit
// --fail-on-policy-error=true is honored with no env var set.
func TestApplyFailOnPolicyError_FlagTrueNoEnv(t *testing.T) {
	defer viper.Reset()
	viper.Reset()
	if err := viper.BindEnv("fail-on-policy-error", "FAIL_ON_POLICY_ERROR"); err != nil {
		t.Fatalf("BindEnv: %v", err)
	}

	cmd := newFailOnPolicyErrorCmd()
	if err := cmd.Flags().Set(flagFailOnPolicyError, "true"); err != nil {
		t.Fatalf("set flag: %v", err)
	}
	applyFailOnPolicyError(cmd)

	if !viper.GetBool("fail-on-policy-error") {
		t.Error("explicit --fail-on-policy-error=true should be honored")
	}
}

// TestApplyFailOnPolicyError_NeitherSet: no flag and no env → false (default,
// backwards compatible).
func TestApplyFailOnPolicyError_NeitherSet(t *testing.T) {
	defer viper.Reset()
	viper.Reset()
	if err := viper.BindEnv("fail-on-policy-error", "FAIL_ON_POLICY_ERROR"); err != nil {
		t.Fatalf("BindEnv: %v", err)
	}

	cmd := newFailOnPolicyErrorCmd()
	applyFailOnPolicyError(cmd)

	if viper.GetBool("fail-on-policy-error") {
		t.Error("with neither flag nor env set, fail-on-policy-error should be false")
	}
}
