package github

import (
	"os"

	"github.com/google/go-github/v89/github"
	"github.com/spf13/viper"
)

// retrieves gh token from multiple sources in order of preference:
// 1. viper config (used by CLI)
// 2. environment variables (GITHUB_TOKEN, GH_TOKEN, GITHUB_AUTH_TOKEN)
func GetToken() string {
	// check viper config first (CLI usage)
	if token := viper.GetString("token"); token != "" {
		return token
	}

	// fallback to environment variables
	for _, envVar := range []string{"GITHUB_TOKEN", "GH_TOKEN", "GITHUB_AUTH_TOKEN"} {
		if token := os.Getenv(envVar); token != "" {
			return token
		}
	}

	return ""
}

// creates a new GitHub client with authentication token.
// returns a client with auth token if available, or unauthenticated client otherwise.
func NewClient() (*github.Client, error) {
	token := GetToken()
	if token != "" {
		return github.NewClient(github.WithAuthToken(token))
	}
	return github.NewClient()
}
