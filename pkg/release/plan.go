package release

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/liatrio/autogov-verify/pkg/mutate"
	"gopkg.in/yaml.v3"
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

// ParsedCommit represents a parsed conventional commit
type ParsedCommit struct {
	Hash     string `json:"hash" yaml:"hash"`
	Type     string `json:"type" yaml:"type"`                       // feat, fix, docs, etc.
	Scope    string `json:"scope,omitempty" yaml:"scope,omitempty"` // optional scope
	Subject  string `json:"subject" yaml:"subject"`                 // commit subject line
	Body     string `json:"body,omitempty" yaml:"body,omitempty"`   // optional body
	Breaking bool   `json:"breaking" yaml:"breaking"`               // is this a breaking change?
	Raw      string `json:"raw" yaml:"raw"`                         // original commit message
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

	// open repository
	repo, err := OpenRepository(opts.RepoPath)
	if err != nil {
		return nil, err
	}

	// get repository name
	repoName := GetRepositoryName(repo)

	// discover latest tag (use FromRef if specified)
	var currentVersion *Version
	var tagName string
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

	// handle no tags case
	if currentVersion == nil {
		currentVersion = ZeroVersion()
	}

	// get commits since tag (use ToRef for target)
	toRef := opts.ToRef
	if toRef == "" {
		toRef = "HEAD"
	}
	commits, err := GetCommitsSinceTag(repo, tagName, toRef, opts.FirstParent)
	if err != nil {
		return nil, fmt.Errorf("failed to get commits: %w", err)
	}

	// parse commits
	parsedCommits := ParseCommits(commits)

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
		changelog, err := GenerateChangelogPreview(parsedCommits, nextVersion.String())
		if err != nil {
			return nil, fmt.Errorf("failed to generate changelog: %w", err)
		}
		plan.ChangelogPreview = changelog
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
func previewMutations(repoPath, configPath, version string) ([]FileMutation, error) {
	config, err := mutate.LoadConfig(configPath)
	if err != nil {
		return nil, err
	}

	results, err := mutate.DryRunMutations(repoPath, config, version)
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
		output += fmt.Sprintf("💥 Breaking Changes (%d)\n", len(p.BreakingChanges))
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
