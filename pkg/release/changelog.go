package release

import (
	"bytes"
	"sort"
	"text/template"
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

// ChangelogOptions contains options for changelog generation
type ChangelogOptions struct {
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
### 💥 Breaking Changes

{{range .BreakingChanges}}- {{.}}
{{end}}
{{end}}{{range .Groups}}{{if .Commits}}
### {{.Info.Emoji}} {{.Info.ChangelogName}}

{{range .Commits}}- {{if .Scope}}**{{.Scope}}:** {{end}}{{.Subject}} ({{shortHash .Hash}})
{{end}}{{end}}{{end}}`

// ChangelogGroup represents a group of commits in the changelog
type ChangelogGroup struct {
	Type    string
	Info    CommitTypeInfo
	Commits []ParsedCommit
}

// ChangelogData contains data for changelog template rendering
type ChangelogData struct {
	Version         string
	BreakingChanges []string
	Groups          []ChangelogGroup
}

// GenerateChangelog creates a changelog preview from commits
func GenerateChangelog(commits []ParsedCommit, opts *ChangelogOptions) (string, error) {
	if opts == nil {
		opts = &ChangelogOptions{}
	}

	// group commits by type
	groups := GroupCommitsByType(commits)

	// build ordered changelog groups
	var orderedGroups []ChangelogGroup
	for _, commitType := range changelogTypeOrder {
		commitList, ok := groups[commitType]
		if !ok || len(commitList) == 0 {
			continue
		}

		// skip non-releasable types unless IncludeAll is set
		info := GetCommitTypeInfo(commitType)
		if !opts.IncludeAll && info.BumpType == BumpNone && commitType != "other" {
			// still include if any commits are breaking
			hasBreaking := false
			for _, c := range commitList {
				if c.Breaking {
					hasBreaking = true
					break
				}
			}
			if !hasBreaking {
				continue
			}
		}

		orderedGroups = append(orderedGroups, ChangelogGroup{
			Type:    commitType,
			Info:    info,
			Commits: commitList,
		})
	}

	// extract breaking changes
	breakingChanges := ExtractBreakingChanges(commits)

	// prepare template data
	data := ChangelogData{
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
// Returns an error if changelog generation fails instead of embedding error in string
func GenerateChangelogPreview(commits []ParsedCommit, nextVersion string) (string, error) {
	opts := &ChangelogOptions{
		Version:    nextVersion,
		IncludeAll: false,
	}

	return GenerateChangelog(commits, opts)
}

// GetCommitStats returns statistics about the commits
func GetCommitStats(commits []ParsedCommit) map[string]int {
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

// SortCommitsByType sorts commits by type according to changelog order
func SortCommitsByType(commits []ParsedCommit) []ParsedCommit {
	typeOrder := make(map[string]int)
	for i, t := range changelogTypeOrder {
		typeOrder[t] = i
	}

	sorted := make([]ParsedCommit, len(commits))
	copy(sorted, commits)

	sort.SliceStable(sorted, func(i, j int) bool {
		orderI, okI := typeOrder[sorted[i].Type]
		orderJ, okJ := typeOrder[sorted[j].Type]

		if !okI {
			orderI = len(changelogTypeOrder)
		}
		if !okJ {
			orderJ = len(changelogTypeOrder)
		}

		return orderI < orderJ
	})

	return sorted
}
