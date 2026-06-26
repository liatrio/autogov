package release

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/liatrio/autogov/pkg/helper/changelog"
	githelper "github.com/liatrio/autogov/pkg/helper/git"
	"github.com/liatrio/autogov/pkg/helper/version"
	"github.com/liatrio/autogov/pkg/mutate"
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
	Commits         []version.ParsedCommit `json:"commits" yaml:"commits"`
	BreakingChanges []string               `json:"breaking_changes" yaml:"breaking_changes"`

	// changelog
	ChangelogPreview string `json:"changelog_preview" yaml:"changelog_preview"`

	// file mutations
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
	// GitHub token; when set and ReleaseAPI is nil, an API client is built from it
	// (lets API mode discover tags/commits without a full local clone)
	Token string
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

// planState holds the version/commit data resolved for a release plan.
type planState struct {
	currentVersion *version.Version
	tagName        string
	parsedCommits  []version.ParsedCommit
	apiSucceeded   bool
}

// GeneratePlan generates a complete release plan
func GeneratePlan(opts *PlanOptions) (*ReleasePlan, error) {
	if opts == nil {
		opts = DefaultPlanOptions()
	}

	if err := ValidateMode(opts.Mode); err != nil {
		return nil, err
	}

	if err := prepareReleaseAPI(opts); err != nil {
		return nil, err
	}

	// open repository
	repo, err := githelper.OpenRepository(opts.RepoPath)
	if err != nil {
		return nil, err
	}

	// get repository name
	repoName := githelper.GetRepositoryName(repo)

	// resolve base version and commits (via API where possible, else local)
	state, err := resolvePlanState(opts, repo, repoName)
	if err != nil {
		return nil, err
	}

	parsedCommits := state.parsedCommits

	// filter to releasable commits for version computation
	releasableCommits := version.FilterReleasableCommits(parsedCommits)

	// compute next version
	nextVersion, bumpType := version.ComputeNextVersion(state.currentVersion, releasableCommits)

	// create release plan
	plan := &ReleasePlan{
		GeneratedAt:     time.Now(),
		Repository:      repoName,
		CurrentVersion:  state.currentVersion.String(),
		NextVersion:     nextVersion.String(),
		BumpType:        string(bumpType),
		Commits:         parsedCommits,
		BreakingChanges: version.ExtractBreakingChanges(parsedCommits),
		ReleaseNeeded:   bumpType != version.BumpNone,
	}

	if err := finalizePlan(opts, plan, nextVersion); err != nil {
		return nil, err
	}

	return plan, nil
}

// resolvePlanState discovers the base version and commits for the plan, using
// the GitHub API where possible and falling back to local go-git otherwise.
func resolvePlanState(opts *PlanOptions, repo *git.Repository, repoFullName string) (*planState, error) {
	parts := strings.SplitN(repoFullName, "/", 2)

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

	state := &planState{}

	if useAPI {
		if err := resolveViaAPI(opts, repo, owner, repoShortName, state); err != nil {
			return nil, err
		}
	}

	if !state.apiSucceeded {
		// local mode: use go-git for tag discovery and commit walking
		if err := resolveViaLocal(opts, repo, state); err != nil {
			return nil, err
		}
	}

	return state, nil
}

// finalizePlan fills in the reason, changelog preview, and file mutations.
func finalizePlan(opts *PlanOptions, plan *ReleasePlan, nextVersion *version.Version) error {
	// set reason if no release needed
	if !plan.ReleaseNeeded {
		if len(plan.Commits) == 0 {
			plan.Reason = "no commits since last release"
		} else {
			plan.Reason = "no releasable commits (only docs, chore, etc.)"
		}
		return nil
	}

	// generate changelog preview
	changelogText, err := changelog.GenerateChangelogPreview(plan.Commits, nextVersion.String())
	if err != nil {
		return fmt.Errorf("failed to generate changelog: %w", err)
	}
	plan.ChangelogPreview = changelogText

	// populate file mutations if config provided
	if opts.MutationsConfig != "" {
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

	return nil
}

// prepareReleaseAPI builds the GitHub release service from the token when one
// wasn't supplied, then enforces the API-mode token requirement.
func prepareReleaseAPI(opts *PlanOptions) error {
	// build the GitHub release service from the token if one wasn't supplied —
	// lets API mode discover tags/commits without a full local clone
	if opts.Token != "" && opts.ReleaseAPI == nil {
		releaseAPI, err := newGitHubReleaseService(opts.Token)
		if err != nil {
			return err
		}
		opts.ReleaseAPI = releaseAPI
	}

	// fail early if api mode requires a token
	if opts.Mode == ModeAPI && opts.ReleaseAPI == nil {
		return fmt.Errorf("mode=api requires a GitHub API client (set --mode=api with a token)")
	}

	return nil
}

// resolveViaAPI discovers the base tag and commits using the GitHub API,
// falling back to local git (unless mode=api) on any recoverable error.
func resolveViaAPI(opts *PlanOptions, repo *git.Repository, owner, repoShortName string, state *planState) error {
	// get local HEAD SHA (works even with shallow clone or detached HEAD)
	head, headErr := repo.Head()
	if headErr != nil {
		if opts.Mode == ModeAPI {
			return fmt.Errorf("failed to get HEAD: %w", headErr)
		}
		fmt.Fprintf(os.Stderr, "using local git for tag discovery (reason: %v)\n", headErr)
		return nil
	}

	headSHA := head.Hash().String()
	ctx := context.Background()

	// API tag discovery
	sortedTags, tagsErr := listTagsFromAPI(ctx, opts.ReleaseAPI, owner, repoShortName)
	if tagsErr != nil {
		if opts.Mode == ModeAPI {
			return fmt.Errorf("API tag discovery failed: %w", tagsErr)
		}
		fmt.Fprintf(os.Stderr, "using local git for tag discovery (reason: %v)\n", tagsErr)
		return nil
	}

	fmt.Fprintf(os.Stderr, "using GitHub API for tag discovery\n")
	state.currentVersion, state.tagName = resolveAPIBaseVersion(sortedTags)

	// no tags: fall back to local for commit walking (need full history)
	if state.tagName == "" {
		if opts.Mode == ModeAPI {
			return fmt.Errorf("no tags found; API mode cannot walk commits without a base tag")
		}
		fmt.Fprintf(os.Stderr, "using local git for commit walking (reason: no tags found)\n")
		return nil
	}

	// API commit walking — only when we have a base tag
	rawCmts, cmtErr := getCommitsFromAPI(ctx, opts.ReleaseAPI, owner, repoShortName, state.tagName, headSHA)
	if cmtErr != nil {
		if opts.Mode == ModeAPI {
			return fmt.Errorf("API commit walking failed: %w", cmtErr)
		}
		fmt.Fprintf(os.Stderr, "using local git for commit walking (reason: %v)\n", cmtErr)
		return nil
	}

	state.parsedCommits = parseRawCommits(rawCmts)
	state.apiSucceeded = true
	return nil
}

// resolveAPIBaseVersion picks the base version/tag from API-sorted tags.
func resolveAPIBaseVersion(sortedTags []string) (*version.Version, string) {
	if len(sortedTags) == 0 {
		return version.ZeroVersion(), ""
	}
	tagName := sortedTags[0]
	if v, parseErr := version.ParseVersion(tagName); parseErr == nil {
		return v, tagName
	}
	return version.ZeroVersion(), tagName
}

// resolveViaLocal discovers the base tag and commits using local go-git.
func resolveViaLocal(opts *PlanOptions, repo *git.Repository, state *planState) error {
	var err error
	if opts.FromRef != "" {
		state.currentVersion, err = version.ParseVersion(opts.FromRef)
		if err != nil {
			return fmt.Errorf("invalid from-ref version: %w", err)
		}
		state.tagName = opts.FromRef
	} else {
		state.currentVersion, state.tagName, err = githelper.DiscoverLatestTag(repo, opts.FirstParent)
		if err != nil {
			return fmt.Errorf("failed to discover latest tag: %w", err)
		}
	}

	if state.currentVersion == nil {
		state.currentVersion = version.ZeroVersion()
	}

	toRef := opts.ToRef
	if toRef == "" {
		toRef = "HEAD"
	}
	commits, commitsErr := githelper.GetCommitsSinceTag(repo, state.tagName, toRef, opts.FirstParent)
	if commitsErr != nil {
		return fmt.Errorf("failed to get commits: %w", commitsErr)
	}
	state.parsedCommits = githelper.ParseCommits(commits)
	return nil
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
