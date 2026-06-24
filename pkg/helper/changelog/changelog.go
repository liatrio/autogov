package changelog

import (
	"bytes"
	"text/template"

	"github.com/liatrio/autogov/pkg/helper/version"
)

// changelog type ordering for consistent output
var changelogTypeOrder = []string{
	"feat",
	"fix",
	"perf",
	"refactor",
	"docs",
	"test",
	"build",
	"ci",
	"chore",
	"style",
	"revert",
	"other",
}

// Options contains options for changelog generation
type Options struct {
	// version being released
	Version string
	// include non-releasable commit types
	IncludeAll bool
	// custom template (uses default if empty)
	Template string
}

// default changelog template
const defaultChangelogTemplate = `## {{.Version}}
{{if .BreakingChanges}}
### Breaking Changes

{{range .BreakingChanges}}- {{.}}
{{end}}
{{end}}{{range .Groups}}{{if .Commits}}
### {{.Info.ChangelogName}}

{{range .Commits}}- {{if .Scope}}**{{.Scope}}:** {{end}}{{.Subject}} ({{shortHash .Hash}})
{{end}}{{end}}{{end}}`

// Group represents a group of commits in the changelog
type Group struct {
	Type    string
	Info    version.CommitTypeInfo
	Commits []version.ParsedCommit
}

// Data contains data for changelog template rendering
type Data struct {
	Version         string
	BreakingChanges []string
	Groups          []Group
}

// shouldIncludeGroup returns true if a commit group should be included in changelog output
func shouldIncludeGroup(commitType string, commitList []version.ParsedCommit, includeAll bool) bool {
	info := version.GetCommitTypeInfo(commitType)
	if includeAll || info.BumpType != version.BumpNone || commitType == "other" {
		return true
	}
	// include non-releasable types only if they contain breaking changes
	for _, c := range commitList {
		if c.Breaking {
			return true
		}
	}
	return false
}

// GenerateChangelog creates a changelog preview from commits
func GenerateChangelog(commits []version.ParsedCommit, opts *Options) (string, error) {
	if opts == nil {
		opts = &Options{}
	}

	// group commits by type
	groups := version.GroupCommitsByType(commits)

	// build ordered changelog groups
	var orderedGroups []Group
	for _, commitType := range changelogTypeOrder {
		commitList, ok := groups[commitType]
		if !ok || len(commitList) == 0 {
			continue
		}

		if !shouldIncludeGroup(commitType, commitList, opts.IncludeAll) {
			continue
		}

		orderedGroups = append(orderedGroups, Group{
			Type:    commitType,
			Info:    version.GetCommitTypeInfo(commitType),
			Commits: commitList,
		})
	}

	// extract breaking changes
	breakingChanges := version.ExtractBreakingChanges(commits)

	// prepare template data
	data := Data{
		Version:         opts.Version,
		BreakingChanges: breakingChanges,
		Groups:          orderedGroups,
	}

	// use custom template or default
	tmplStr := opts.Template
	if tmplStr == "" {
		tmplStr = defaultChangelogTemplate
	}

	// template functions
	funcs := template.FuncMap{
		"shortHash": func(hash string) string {
			if len(hash) > 7 {
				return hash[:7]
			}
			return hash
		},
	}

	tmpl, err := template.New("changelog").Funcs(funcs).Parse(tmplStr)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// GenerateChangelogPreview creates a brief changelog preview suitable for release plan output
func GenerateChangelogPreview(commits []version.ParsedCommit, nextVersion string) (string, error) {
	opts := &Options{
		Version:    nextVersion,
		IncludeAll: false,
	}

	return GenerateChangelog(commits, opts)
}

// GetCommitStats returns statistics about the commits
func GetCommitStats(commits []version.ParsedCommit) map[string]int {
	stats := make(map[string]int)

	for _, c := range commits {
		stats[c.Type]++
		if c.Breaking {
			stats["breaking"]++
		}
	}

	stats["total"] = len(commits)
	return stats
}

// JSON represents the JSON output format for changelog generation
type JSON struct {
	Version         string         `json:"version,omitempty"`
	BreakingChanges []string       `json:"breaking_changes,omitempty"`
	Groups          []GroupJSON    `json:"groups"`
	Stats           map[string]int `json:"stats"`
}

// GroupJSON represents a commit group in JSON output
type GroupJSON struct {
	Type    string       `json:"type"`
	Name    string       `json:"name"`
	Commits []CommitJSON `json:"commits"`
}

// CommitJSON represents a single commit in JSON output
type CommitJSON struct {
	Hash     string `json:"hash"`
	Type     string `json:"type"`
	Scope    string `json:"scope,omitempty"`
	Subject  string `json:"subject"`
	Breaking bool   `json:"breaking,omitempty"`
}

// GenerateChangelogJSON creates a structured JSON changelog from commits
func GenerateChangelogJSON(commits []version.ParsedCommit, opts *Options) *JSON {
	if opts == nil {
		opts = &Options{}
	}

	groups := version.GroupCommitsByType(commits)

	jsonGroups := make([]GroupJSON, 0)
	for _, commitType := range changelogTypeOrder {
		commitList, ok := groups[commitType]
		if !ok || len(commitList) == 0 {
			continue
		}

		if !shouldIncludeGroup(commitType, commitList, opts.IncludeAll) {
			continue
		}

		info := version.GetCommitTypeInfo(commitType)
		jsonCommits := make([]CommitJSON, 0, len(commitList))
		for _, c := range commitList {
			jc := CommitJSON{
				Hash:    c.Hash,
				Type:    c.Type,
				Scope:   c.Scope,
				Subject: c.Subject,
			}
			if c.Breaking {
				jc.Breaking = true
			}
			jsonCommits = append(jsonCommits, jc)
		}

		jsonGroups = append(jsonGroups, GroupJSON{
			Type:    commitType,
			Name:    info.ChangelogName,
			Commits: jsonCommits,
		})
	}

	return &JSON{
		Version:         opts.Version,
		BreakingChanges: version.ExtractBreakingChanges(commits),
		Groups:          jsonGroups,
		Stats:           GetCommitStats(commits),
	}
}
