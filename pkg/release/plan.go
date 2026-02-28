package release

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/liatrio/autogov/pkg/helper/changelog"
	githelper "github.com/liatrio/autogov/pkg/helper/git"
	"github.com/liatrio/autogov/pkg/helper/version"
	"github.com/liatrio/autogov/pkg/mutate"
	"gopkg.in/yaml.v3"
)

// Backward-compatibility aliases and re-exports.
// TODO(2-12): Remove these once all callers import from pkg/helper/* directly.
// These exist to avoid breaking existing code during the story 2-10 extraction.

// ParsedCommit is an alias for version.ParsedCommit for backward compatibility.
type ParsedCommit = version.ParsedCommit

// BumpType is an alias for version.BumpType for backward compatibility
type BumpType = version.BumpType

// Version is an alias for version.Version for backward compatibility
type Version = version.Version

// CommitTypeInfo is an alias for version.CommitTypeInfo for backward compatibility
type CommitTypeInfo = version.CommitTypeInfo

// Re-export version constants for backward compatibility
const (
	BumpMajor = version.BumpMajor
	BumpMinor = version.BumpMinor
	BumpPatch = version.BumpPatch
	BumpNone  = version.BumpNone
)

// Re-export version functions for backward compatibility
var (
	ParseVersion           = version.ParseVersion
	ZeroVersion            = version.ZeroVersion
	ComputeNextVersion     = version.ComputeNextVersion
	ParseConventionalCommit = version.ParseConventionalCommit
	FilterReleasableCommits = version.FilterReleasableCommits
	ExtractBreakingChanges  = version.ExtractBreakingChanges
	GroupCommitsByType      = version.GroupCommitsByType
	GetCommitTypeInfo       = version.GetCommitTypeInfo
)

// Re-export git helper functions for backward compatibility
var (
	OpenRepository   = githelper.OpenRepository
	DiscoverLatestTag = githelper.DiscoverLatestTag
	GetCommitsSinceTag = githelper.GetCommitsSinceTag
	GetRepositoryName  = githelper.GetRepositoryName
	ParseCommits       = githelper.ParseCommits
)

// ChangelogOptions is an alias for changelog.Options for backward compatibility
type ChangelogOptions = changelog.Options

// ChangelogJSON is an alias for changelog.JSON for backward compatibility
type ChangelogJSON = changelog.JSON

// ChangelogGroupJSON is an alias for changelog.GroupJSON for backward compatibility
type ChangelogGroupJSON = changelog.GroupJSON

// CommitJSON is an alias for changelog.CommitJSON for backward compatibility
type CommitJSON = changelog.CommitJSON

// Re-export changelog functions for backward compatibility
var (
	GenerateChangelog        = changelog.GenerateChangelog
	GenerateChangelogPreview = changelog.GenerateChangelogPreview
	GenerateChangelogJSON    = changelog.GenerateChangelogJSON
	GetCommitStats           = changelog.GetCommitStats
)

// ReleasePlan contains all information about a planned release
type ReleasePlan struct {
	// metadata
	GeneratedAt time.Time `json:"generated_at" yaml:"generated_at"`
	Repository  string    `json:"repository" yaml:"repository"`

	// version info
	CurrentVersion string `json:"current_version" yaml:"current_version"`
	NextVersion    string `json:"next_version" yaml:"next_version"`
	BumpType       string `json:"bump_type" yaml:"bump_type"` // major/minor/patch/none

	// commits
	Commits         []ParsedCommit `json:"commits" yaml:"commits"`
	BreakingChanges []string       `json:"breaking_changes" yaml:"breaking_changes"`

	// changelog
	ChangelogPreview string `json:"changelog_preview" yaml:"changelog_preview"`

	// file mutations (placeholder for Story 2.3)
	FileMutations []FileMutation `json:"file_mutations,omitempty" yaml:"file_mutations,omitempty"`

	// status
	ReleaseNeeded bool   `json:"release_needed" yaml:"release_needed"`
	Reason        string `json:"reason,omitempty" yaml:"reason,omitempty"`
}

// FileMutation represents a file change that would occur during release
type FileMutation struct {
	Path     string `json:"path" yaml:"path"`
	Type     string `json:"type" yaml:"type"`           // jsonPath, yamlPath, regex
	Field    string `json:"field" yaml:"field"`         // field being modified
	OldValue string `json:"old_value" yaml:"old_value"` // current value
	NewValue string `json:"new_value" yaml:"new_value"` // value after release
}

// PlanOptions contains options for generating a release plan
type PlanOptions struct {
	// base ref to compare from (default: latest tag)
	FromRef string
	// target ref to compare to (default: HEAD)
	ToRef string
	// only follow first parent in merge commits
	FirstParent bool
	// path to repository (default: current directory)
	RepoPath string
	// output format (text, json, yaml)
	OutputFormat string
	// path to mutations config file (optional)
	MutationsConfig string
	// release mode: "auto" (default), "api", "local"
	Mode ReleaseMode
	// GitHub API client for API mode tag/commit discovery (optional)
	ReleaseAPI ReleaseService
	// branch name used as head for API compare (required for API mode)
	Branch string
}

// DefaultPlanOptions returns options with sensible defaults
func DefaultPlanOptions() *PlanOptions {
	return &PlanOptions{
		FromRef:      "",
		ToRef:        "HEAD",
		FirstParent:  false,
		RepoPath:     ".",
		OutputFormat: "text",
	}
}

// GeneratePlan generates a complete release plan
func GeneratePlan(opts *PlanOptions) (*ReleasePlan, error) {
	if opts == nil {
		opts = DefaultPlanOptions()
	}

	if err := ValidateMode(opts.Mode); err != nil {
		return nil, err
	}

	// fail early if api mode requires a token
	if opts.Mode == ModeAPI && opts.ReleaseAPI == nil {
		return nil, fmt.Errorf("mode=api requires a GitHub API client (ReleaseAPI)")
	}

	// open repository
	repo, err := OpenRepository(opts.RepoPath)
	if err != nil {
		return nil, err
	}

	// get repository name
	repoFullName := GetRepositoryName(repo)
	parts := strings.SplitN(repoFullName, "/", 2)
	repoName := repoFullName

	// determine owner/repo for API mode
	var owner, repoShortName string
	if len(parts) == 2 {
		owner, repoShortName = parts[0], parts[1]
	}

	// decide whether to use GitHub API for tag discovery and commit walking
	useAPI := opts.Mode != ModeLocal &&
		opts.ReleaseAPI != nil &&
		owner != "" && repoShortName != "" &&
		opts.FromRef == "" // FromRef overrides to local always

	var currentVersion *Version
	var tagName string
	var parsedCommits []ParsedCommit
	apiSucceeded := false

	if useAPI {
		// get local HEAD SHA (works even with shallow clone or detached HEAD)
		head, headErr := repo.Head()
		if headErr != nil {
			if opts.Mode == ModeAPI {
				return nil, fmt.Errorf("failed to get HEAD: %w", headErr)
			}
			fmt.Fprintf(os.Stderr, "using local git for tag discovery (reason: %v)\n", headErr)
		} else {
			headSHA := head.Hash().String()
			ctx := context.Background()

			// API tag discovery
			sortedTags, tagsErr := listTagsFromAPI(ctx, opts.ReleaseAPI, owner, repoShortName)
			if tagsErr != nil {
				if opts.Mode == ModeAPI {
					return nil, fmt.Errorf("API tag discovery failed: %w", tagsErr)
				}
				fmt.Fprintf(os.Stderr, "using local git for tag discovery (reason: %v)\n", tagsErr)
			} else {
				fmt.Fprintf(os.Stderr, "using GitHub API for tag discovery\n")
				if len(sortedTags) == 0 {
					currentVersion = ZeroVersion()
					tagName = ""
				} else {
					tagName = sortedTags[0]
					if v, parseErr := ParseVersion(tagName); parseErr == nil {
						currentVersion = v
					} else {
						currentVersion = ZeroVersion()
					}
				}

				// API commit walking — only when we have a base tag
				if tagName != "" {
					rawCmts, cmtErr := getCommitsFromAPI(ctx, opts.ReleaseAPI, owner, repoShortName, tagName, headSHA)
					if cmtErr != nil {
						if opts.Mode == ModeAPI {
							return nil, fmt.Errorf("API commit walking failed: %w", cmtErr)
						}
						fmt.Fprintf(os.Stderr, "using local git for commit walking (reason: %v)\n", cmtErr)
					} else {
						parsedCommits = parseRawCommits(rawCmts)
						apiSucceeded = true
					}
				} else {
					// no tags: fall back to local for commit walking (need full history)
					if opts.Mode == ModeAPI {
						return nil, fmt.Errorf("no tags found; API mode cannot walk commits without a base tag")
					}
					fmt.Fprintf(os.Stderr, "using local git for commit walking (reason: no tags found)\n")
				}
			}
		}
	}

	if !apiSucceeded {
		// local mode: use go-git for tag discovery and commit walking
		if opts.FromRef != "" {
			currentVersion, err = ParseVersion(opts.FromRef)
			if err != nil {
				return nil, fmt.Errorf("invalid from-ref version: %w", err)
			}
			tagName = opts.FromRef
		} else {
			currentVersion, tagName, err = DiscoverLatestTag(repo, opts.FirstParent)
			if err != nil {
				return nil, fmt.Errorf("failed to discover latest tag: %w", err)
			}
		}

		if currentVersion == nil {
			currentVersion = ZeroVersion()
		}

		toRef := opts.ToRef
		if toRef == "" {
			toRef = "HEAD"
		}
		commits, commitsErr := GetCommitsSinceTag(repo, tagName, toRef, opts.FirstParent)
		if commitsErr != nil {
			return nil, fmt.Errorf("failed to get commits: %w", commitsErr)
		}
		parsedCommits = ParseCommits(commits)
	}

	// filter to releasable commits for version computation
	releasableCommits := FilterReleasableCommits(parsedCommits)

	// compute next version
	nextVersion, bumpType := ComputeNextVersion(currentVersion, releasableCommits)

	// create release plan
	plan := &ReleasePlan{
		GeneratedAt:     time.Now(),
		Repository:      repoName,
		CurrentVersion:  currentVersion.String(),
		NextVersion:     nextVersion.String(),
		BumpType:        string(bumpType),
		Commits:         parsedCommits,
		BreakingChanges: ExtractBreakingChanges(parsedCommits),
		ReleaseNeeded:   bumpType != BumpNone,
	}

	// set reason if no release needed
	if !plan.ReleaseNeeded {
		if len(parsedCommits) == 0 {
			plan.Reason = "no commits since last release"
		} else {
			plan.Reason = "no releasable commits (only docs, chore, etc.)"
		}
	} else {
		// generate changelog preview
		changelogText, err := GenerateChangelogPreview(parsedCommits, nextVersion.String())
		if err != nil {
			return nil, fmt.Errorf("failed to generate changelog: %w", err)
		}
		plan.ChangelogPreview = changelogText
	}

	// populate file mutations if config provided
	if opts.MutationsConfig != "" && plan.ReleaseNeeded {
		mutations, err := previewMutations(opts.RepoPath, opts.MutationsConfig, nextVersion.StringWithoutV())
		if err != nil {
			// non-fatal: log warning but don't fail the plan
			plan.FileMutations = []FileMutation{{
				Path: opts.MutationsConfig, Type: "error", Field: "", OldValue: "", NewValue: err.Error(),
			}}
		} else {
			plan.FileMutations = mutations
		}
	}

	return plan, nil
}

// previewMutations loads mutation config and performs a dry-run
func previewMutations(repoPath, configPath, versionStr string) ([]FileMutation, error) {
	config, err := mutate.LoadConfig(configPath)
	if err != nil {
		return nil, err
	}

	results, err := mutate.DryRunMutations(repoPath, config, versionStr)
	if err != nil {
		return nil, err
	}

	var mutations []FileMutation
	for _, r := range results {
		fm := FileMutation{
			Path:     r.Rule.Path,
			Type:     r.Rule.Type,
			Field:    r.Rule.Field,
			OldValue: r.OldValue,
			NewValue: r.NewValue,
		}
		// propagate per-rule errors so the plan shows failures
		if r.Error != "" {
			fm.Type = "error"
			fm.NewValue = r.Error
		}
		mutations = append(mutations, fm)
	}
	return mutations, nil
}

// ToJSON converts the plan to JSON format
func (p *ReleasePlan) ToJSON() ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}

// ToYAML converts the plan to YAML format
func (p *ReleasePlan) ToYAML() ([]byte, error) {
	return yaml.Marshal(p)
}

// ToText converts the plan to human-readable text format
func (p *ReleasePlan) ToText() string {
	if !p.ReleaseNeeded {
		return fmt.Sprintf("No release needed: %s\n", p.Reason)
	}

	output := "Release Plan\n"
	output += "============\n\n"
	output += fmt.Sprintf("Repository:      %s\n", p.Repository)
	output += fmt.Sprintf("Current Version: %s\n", p.CurrentVersion)
	output += fmt.Sprintf("Next Version:    %s\n", p.NextVersion)
	output += fmt.Sprintf("Bump Type:       %s\n", p.BumpType)
	output += fmt.Sprintf("Generated At:    %s\n\n", p.GeneratedAt.Format(time.RFC3339))

	if len(p.BreakingChanges) > 0 {
		output += fmt.Sprintf("Breaking Changes (%d)\n", len(p.BreakingChanges))
		output += "------------------------\n"
		for _, bc := range p.BreakingChanges {
			output += fmt.Sprintf("  - %s\n", bc)
		}
		output += "\n"
	}

	output += fmt.Sprintf("Commits (%d)\n", len(p.Commits))
	output += "------------\n"
	for _, c := range p.Commits {
		breakingMark := ""
		if c.Breaking {
			breakingMark = "!"
		}
		shortHash := shortHashSafe(c.Hash)
		if c.Scope != "" {
			output += fmt.Sprintf("  %s %s(%s)%s: %s\n", shortHash, c.Type, c.Scope, breakingMark, c.Subject)
		} else {
			output += fmt.Sprintf("  %s %s%s: %s\n", shortHash, c.Type, breakingMark, c.Subject)
		}
	}

	if p.ChangelogPreview != "" {
		output += "\nChangelog Preview\n"
		output += "-----------------\n"
		output += p.ChangelogPreview
	}

	return output
}

// shortHashSafe returns first 7 chars of hash, or full hash if shorter
func shortHashSafe(hash string) string {
	if len(hash) > 7 {
		return hash[:7]
	}
	return hash
}
