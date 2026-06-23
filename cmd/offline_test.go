package cmd

import "testing"

// the offline command must register --cert-identity-list and --no-cache so the
// standalone `autogov offline` path has the same signer-allowlist surface as
// `autogov verify attestation` (cobra otherwise rejects the unknown flags).
func TestOfflineCmdRegistersCertIdentityAllowlistFlags(t *testing.T) {
	for _, name := range []string{flagCertIdentityList, flagNoCache} {
		if offlineCmd.Flags().Lookup(name) == nil {
			t.Errorf("offline command is missing the --%s flag", name)
		}
	}
}
