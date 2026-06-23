package cmd

import "testing"

// offline must register the allowlist flags so cobra accepts them.
func TestOfflineCmdRegistersCertIdentityAllowlistFlags(t *testing.T) {
	for _, name := range []string{flagCertIdentityList, flagNoCache} {
		if offlineCmd.Flags().Lookup(name) == nil {
			t.Errorf("offline command is missing the --%s flag", name)
		}
	}
}
