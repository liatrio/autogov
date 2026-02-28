package git

import (
	"strings"

	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/liatrio/autogov/pkg/helper/version"
)

// ParseCommits converts git commits to ParsedCommits
// non-conventional commits are included with Type="other"
func ParseCommits(commits []*object.Commit) []version.ParsedCommit {
	var parsed []version.ParsedCommit

	for _, c := range commits {
		pc := version.ParseConventionalCommit(c.Hash.String(), c.Message)
		if pc == nil {
			// include non-conventional commits as "other"
			lines := strings.SplitN(c.Message, "\n", 2)
			subject := strings.TrimSpace(lines[0])
			var body string
			if len(lines) > 1 {
				body = strings.TrimSpace(lines[1])
			}

			pc = &version.ParsedCommit{
				Hash:     c.Hash.String(),
				Type:     "other",
				Subject:  subject,
				Body:     body,
				Breaking: false,
				Raw:      c.Message,
			}
		}
		parsed = append(parsed, *pc)
	}

	return parsed
}
