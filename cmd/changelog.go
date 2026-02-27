package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"

	"github.com/liatrio/autogov/pkg/release"
	"github.com/spf13/cobra"
)

var changelogCmd = &cobra.Command{
	Use:   "changelog",
	Short: "Generate changelog from conventional commits",
	Long: `Generate a changelog based on conventional commits.

This command analyzes git history and generates a changelog following
the Keep a Changelog format, organized by commit type (features, fixes, etc.).

Examples:
  # Generate changelog for all releases
  autogov changelog

  # Generate changelog since a specific tag
  autogov changelog --from v1.0.0

  # Generate changelog between two tags
  autogov changelog --from v1.0.0 --to v1.1.0

  # Output as JSON
  autogov changelog --format json

  # Output to a specific file
  autogov changelog --output CHANGELOG.md`,
	RunE: runChangelog,
}

func init() {
	changelogCmd.Flags().String("from", "", "Starting ref (tag/branch/SHA); empty discovers latest tag")
	changelogCmd.Flags().String("to", "HEAD", "Ending ref for changelog generation")
	changelogCmd.Flags().StringP("output", "o", "", "Output file path (default: stdout)")
	changelogCmd.Flags().String("format", "markdown", "Output format: markdown, json")
	changelogCmd.Flags().String("repo-path", ".", "Path to git repository")
	changelogCmd.Flags().Bool("include-all", false, "Include non-releasable commit types (docs, chore, test, etc.)")
	changelogCmd.Flags().Bool("first-parent", false, "Follow only first parent (merge commits) for history")
	changelogCmd.Flags().String("version", "", "Version header; if empty and --to is a semver tag, derived from tag")
}

// semverTagPattern matches semver tags like v1.2.3, v0.1.0-rc.1
var semverTagPattern = regexp.MustCompile(`^v?\d+\.\d+\.\d+(-|$)`)

func runChangelog(cmd *cobra.Command, args []string) error {
	repoPath, _ := cmd.Flags().GetString("repo-path")
	from, _ := cmd.Flags().GetString("from")
	to, _ := cmd.Flags().GetString("to")
	output, _ := cmd.Flags().GetString("output")
	format, _ := cmd.Flags().GetString("format")
	includeAll, _ := cmd.Flags().GetBool("include-all")
	firstParent, _ := cmd.Flags().GetBool("first-parent")
	version, _ := cmd.Flags().GetString("version")

	// 1. Open repo
	repo, err := release.OpenRepository(repoPath)
	if err != nil {
		return fmt.Errorf("changelog: %w", err)
	}

	// 2. Resolve --from: if empty, discover latest tag
	fromRef := from
	if fromRef == "" {
		_, tagName, err := release.DiscoverLatestTag(repo, firstParent)
		if err != nil {
			return fmt.Errorf("changelog: discovering latest tag: %w", err)
		}
		fromRef = tagName // empty string if no tags exist → full history
	}

	// 3. Get commits
	gitCommits, err := release.GetCommitsSinceTag(repo, fromRef, to, firstParent)
	if err != nil {
		return fmt.Errorf("changelog: %w", err)
	}

	if len(gitCommits) == 0 {
		displayFrom := fromRef
		if displayFrom == "" {
			displayFrom = "(root)"
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "No changes found between %s and %s\n", displayFrom, to)
		return nil
	}

	// Sort by author date descending for deterministic output when not using first-parent
	if !firstParent {
		sort.SliceStable(gitCommits, func(i, j int) bool {
			return gitCommits[i].Author.When.After(gitCommits[j].Author.When)
		})
	}

	// 4. Parse commits (after sorting so order is preserved)
	parsed := release.ParseCommits(gitCommits)

	// 5. Resolve version
	if version == "" && semverTagPattern.MatchString(to) {
		version = to
	}

	// 6. Generate output
	var result string
	switch format {
	case "json":
		jsonData := release.GenerateChangelogJSON(parsed, &release.ChangelogOptions{
			Version:    version,
			IncludeAll: includeAll,
		})
		jsonBytes, err := json.MarshalIndent(jsonData, "", "  ")
		if err != nil {
			return fmt.Errorf("changelog: marshaling JSON: %w", err)
		}
		result = string(jsonBytes) + "\n"
	case "markdown", "md":
		opts := &release.ChangelogOptions{
			Version:    version,
			IncludeAll: includeAll,
		}
		result, err = release.GenerateChangelog(parsed, opts)
		if err != nil {
			return fmt.Errorf("changelog: generating markdown: %w", err)
		}
	default:
		return fmt.Errorf("changelog: unsupported format %q (use markdown or json)", format)
	}

	// 7. Output
	if output != "" {
		if err := os.WriteFile(output, []byte(result), 0o644); err != nil {
			return fmt.Errorf("changelog: writing output file: %w", err)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Changelog written to %s\n", output)
		return nil
	}

	_, _ = fmt.Fprint(cmd.OutOrStdout(), result)
	return nil
}
