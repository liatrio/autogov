package release

import (
	"regexp"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/object"
)

// conventional commit regex pattern
// format: type(scope)!: subject
var conventionalCommitPattern = regexp.MustCompile(
	`^(\w+)(?:\(([^)]+)\))?(!)?:\s*(.+)$`,
)

// CommitTypeInfo defines properties for a commit type
type CommitTypeInfo struct {
	Emoji         string
	ChangelogName string
	BumpType      BumpType
}

// commit type mappings
var commitTypes = map[string]CommitTypeInfo{
	"feat":     {Emoji: "✨", ChangelogName: "Features", BumpType: BumpMinor},
	"fix":      {Emoji: "🐛", ChangelogName: "Bug Fixes", BumpType: BumpPatch},
	"docs":     {Emoji: "📖", ChangelogName: "Documentation", BumpType: BumpNone},
	"perf":     {Emoji: "⚡️", ChangelogName: "Performance", BumpType: BumpPatch},
	"refactor": {Emoji: "✏️", ChangelogName: "Refactor", BumpType: BumpNone},
	"test":     {Emoji: "🧪", ChangelogName: "Testing", BumpType: BumpNone},
	"build":    {Emoji: "🛠️", ChangelogName: "Build", BumpType: BumpNone},
	"ci":       {Emoji: "🔄", ChangelogName: "CI", BumpType: BumpNone},
	"chore":    {Emoji: "🔧", ChangelogName: "Chores", BumpType: BumpNone},
	"style":    {Emoji: "💄", ChangelogName: "Style", BumpType: BumpNone},
	"revert":   {Emoji: "⏪", ChangelogName: "Reverts", BumpType: BumpPatch},
}

// GetCommitTypeInfo returns info for a commit type, or a default if unknown
func GetCommitTypeInfo(commitType string) CommitTypeInfo {
	if info, ok := commitTypes[strings.ToLower(commitType)]; ok {
		return info
	}
	return CommitTypeInfo{Emoji: "📝", ChangelogName: "Other", BumpType: BumpNone}
}

// ParseConventionalCommit parses a commit message into a ParsedCommit
// returns nil if the message doesn't follow conventional commit format
func ParseConventionalCommit(hash, message string) *ParsedCommit {
	lines := strings.SplitN(message, "\n", 2)
	subject := strings.TrimSpace(lines[0])

	var body string
	if len(lines) > 1 {
		body = strings.TrimSpace(lines[1])
	}

	matches := conventionalCommitPattern.FindStringSubmatch(subject)
	if matches == nil {
		// not a conventional commit
		return nil
	}

	commitType := strings.ToLower(matches[1])
	scope := matches[2]
	breakingMarker := matches[3] == "!"
	commitSubject := matches[4]

	// check for BREAKING CHANGE in body
	breakingInBody := strings.Contains(body, "BREAKING CHANGE:") ||
		strings.Contains(body, "BREAKING-CHANGE:")

	return &ParsedCommit{
		Hash:     hash,
		Type:     commitType,
		Scope:    scope,
		Subject:  commitSubject,
		Body:     body,
		Breaking: breakingMarker || breakingInBody,
		Raw:      message,
	}
}

// ParseCommits converts git commits to ParsedCommits
// non-conventional commits are included with Type="other"
func ParseCommits(commits []*object.Commit) []ParsedCommit {
	var parsed []ParsedCommit

	for _, c := range commits {
		pc := ParseConventionalCommit(c.Hash.String(), c.Message)
		if pc == nil {
			// include non-conventional commits as "other"
			lines := strings.SplitN(c.Message, "\n", 2)
			subject := strings.TrimSpace(lines[0])
			var body string
			if len(lines) > 1 {
				body = strings.TrimSpace(lines[1])
			}

			pc = &ParsedCommit{
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

// FilterReleasableCommits returns only commits that trigger a version bump
func FilterReleasableCommits(commits []ParsedCommit) []ParsedCommit {
	var releasable []ParsedCommit

	for _, c := range commits {
		// breaking changes are always releasable
		if c.Breaking {
			releasable = append(releasable, c)
			continue
		}

		// check if the commit type triggers a bump
		info := GetCommitTypeInfo(c.Type)
		if info.BumpType != BumpNone {
			releasable = append(releasable, c)
		}
	}

	return releasable
}

// ExtractBreakingChanges extracts breaking change descriptions from commits
func ExtractBreakingChanges(commits []ParsedCommit) []string {
	var breaking []string

	for _, c := range commits {
		if !c.Breaking {
			continue
		}

		// format the breaking change description
		desc := c.Subject
		if c.Scope != "" {
			desc = c.Scope + ": " + desc
		}
		breaking = append(breaking, desc)

		// also check for detailed breaking change in body
		if strings.Contains(c.Body, "BREAKING CHANGE:") {
			lines := strings.Split(c.Body, "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "BREAKING CHANGE:") {
					detail := strings.TrimPrefix(line, "BREAKING CHANGE:")
					detail = strings.TrimSpace(detail)
					if detail != "" && detail != desc {
						breaking = append(breaking, detail)
					}
				}
			}
		}
	}

	return breaking
}

// GroupCommitsByType groups commits by their type for changelog generation
func GroupCommitsByType(commits []ParsedCommit) map[string][]ParsedCommit {
	groups := make(map[string][]ParsedCommit)

	for _, c := range commits {
		groups[c.Type] = append(groups[c.Type], c)
	}

	return groups
}
