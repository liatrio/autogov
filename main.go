package main

import (
	"github.com/liatrio/autogov-verify/cmd"
)

// build-time variables set via ldflags
var (
	version    = "dev"
	commit     = "none"
	date       = "unknown"
	OpaVersion = "v1.8.0"
)

func init() {
	// pass build-time variables to cmd package
	cmd.Version = version
	cmd.Commit = commit
	cmd.Date = date
	cmd.OpaVersion = OpaVersion
}

func main() {
	cmd.Execute()
}
