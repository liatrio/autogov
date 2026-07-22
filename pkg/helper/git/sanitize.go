package git

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/storage"
	"github.com/go-git/go-git/v5/storage/filesystem"
)

// sanitizeAttempts counts invocations of the sanitize-and-retry fallback
// path. It has no effect on behavior; it exists so tests can assert the fast
// path (a repo whose config is already valid) never shells out to git.
var sanitizeAttempts atomic.Int64

// go-git v5.19.1's storage/filesystem.ConfigStorage.Config() unconditionally
// calls config.ReadConfig, whose Branch.unmarshal() inline-calls
// Branch.Validate() for every "[branch \"X\"]" subsection. Validate() rejects
// any branch whose merge ref isn't under refs/heads/ (e.g. the
// "refs/pull/<n>/head" that `gh pr checkout` writes), returning the
// unexported sentinel error config.errBranchInvalidMerge ("branch config:
// invalid merge"). git.Open (which git.PlainOpen calls) always calls
// s.Config(), so a single such branch makes the whole repository unopenable
// via go-git even though real git accepts the ref fine, and there is no
// PlainOpenOptions flag to skip the validation.
//
// The workaround below shells out to the real `git` binary to locate the
// repository's git-dir (reusing real git's own, already-correct resolution of
// bare repos / gitdir files / core.worktree / env overrides, rather than
// reimplementing go-git's unexported dotGitToOSFilesystems), reads that
// git-dir's config file, and drops only the offending "merge = <ref>" lines
// inside [branch "..."] subsections before reparsing the result with go-git's
// own, unmodified config.ReadConfig. Every other config line -- remotes,
// rebase, description, other branches, core, user, submodules -- passes
// through byte-for-byte.

// branchConfigErrorMarker is the shared substring of go-git v5's unexported
// branch-config validation sentinel errors (errBranchInvalidMerge,
// errBranchEmptyName, errBranchInvalidRebase). They cannot be imported or
// matched with errors.Is, so we match by error text.
const branchConfigErrorMarker = "branch config:"

var (
	// branchSectionHeaderRe matches a `[branch "name"]` config section header.
	branchSectionHeaderRe = regexp.MustCompile(`(?i)^\s*\[\s*branch\s+"(?:[^"\\]|\\.)*"\s*\]\s*$`)
	// sectionHeaderRe matches any config section header (used to detect leaving
	// a [branch "..."] subsection).
	sectionHeaderRe = regexp.MustCompile(`^\s*\[`)
	// mergeLineRe matches a `merge = <value>` line inside a branch subsection.
	mergeLineRe = regexp.MustCompile(`(?i)^\s*merge\s*=\s*(.*?)\s*$`)
)

// isBranchConfigError reports whether err is (or wraps) one of go-git's
// unexported branch-config validation errors.
func isBranchConfigError(err error) bool {
	return err != nil && strings.Contains(err.Error(), branchConfigErrorMarker)
}

// openWithSanitizedBranchConfig re-opens the repository at path after
// neutralizing any [branch "..."] "merge" lines that point outside
// refs/heads/. It never writes to the repository: sanitization happens only
// over an in-memory copy of the config bytes.
func openWithSanitizedBranchConfig(path string) (*git.Repository, error) {
	sanitizeAttempts.Add(1)

	gitDir, err := resolveGitDir(path)
	if err != nil {
		return nil, fmt.Errorf("locate git-dir: %w", err)
	}

	configPath := filepath.Join(gitDir, "config")
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", configPath, err)
	}

	sanitized := sanitizeBranchMergeRefs(raw)

	cfg, err := gitconfig.ReadConfig(bytes.NewReader(sanitized))
	if err != nil {
		return nil, fmt.Errorf("reparse sanitized config: %w", err)
	}

	fs := osfs.New(gitDir)
	base := filesystem.NewStorage(fs, cache.NewObjectLRUDefault())
	storer := &sanitizedConfigStorer{Storage: base, cfg: cfg}

	var wt billy.Filesystem
	if top, ok := resolveWorkTree(path); ok {
		wt = osfs.New(top)
	}

	repo, err := git.Open(storer, wt)
	if err != nil {
		return nil, fmt.Errorf("open sanitized repository: %w", err)
	}

	return repo, nil
}

// sanitizedConfigStorer decorates a real filesystem storer, returning a
// pre-parsed, sanitized config from Config() instead of re-reading the
// still-invalid file from disk. Every other method is promoted, unchanged,
// from the embedded *filesystem.Storage.
type sanitizedConfigStorer struct {
	*filesystem.Storage
	cfg *gitconfig.Config
}

// Config returns the sanitized, pre-parsed config.
func (s *sanitizedConfigStorer) Config() (*gitconfig.Config, error) {
	return s.cfg, nil
}

// compile-time assertion that sanitizedConfigStorer satisfies storage.Storer.
var _ storage.Storer = (*sanitizedConfigStorer)(nil)

// sanitizeBranchMergeRefs returns a copy of raw with every "merge = <value>"
// line inside a "[branch \"...\"]" subsection dropped when <value> doesn't
// start with "refs/heads/". Every other line, including untouched merge
// lines, is preserved byte-for-byte. This is a deliberately line-oriented
// scan, not a full INI rewrite: go-git's own config.ReadConfig is still the
// only thing that parses the result.
func sanitizeBranchMergeRefs(raw []byte) []byte {
	lines := strings.Split(string(raw), "\n")
	inBranchSection := false

	out := make([]string, 0, len(lines))
	for _, line := range lines {
		switch {
		case branchSectionHeaderRe.MatchString(line):
			inBranchSection = true
		case sectionHeaderRe.MatchString(line):
			inBranchSection = false
		case inBranchSection:
			if m := mergeLineRe.FindStringSubmatch(line); m != nil {
				value := strings.Trim(m[1], `"`)
				if !strings.HasPrefix(value, "refs/heads/") {
					// drop: neutralizes the offending merge ref
					continue
				}
			}
		}
		out = append(out, line)
	}

	return []byte(strings.Join(out, "\n"))
}

// runGit runs `git -C dir <args...>` and returns its stdout. It never
// mutates the repository -- callers only pass read-only subcommands.
func runGit(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), msg)
	}

	return stdout.String(), nil
}

// resolveGitDir locates the real git-dir for path the same way real git
// resolves it (bare repos, gitdir-file worktrees, core.worktree, env
// overrides), by shelling out rather than reimplementing that detection.
func resolveGitDir(path string) (string, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return "", fmt.Errorf("git binary required on PATH for this workaround: %w", err)
	}

	if out, err := runGit(path, "rev-parse", "--absolute-git-dir"); err == nil {
		if dir := strings.TrimSpace(out); dir != "" {
			return dir, nil
		}
	}

	// --absolute-git-dir was added in git 2.13; fall back to --git-dir (which
	// may be relative) for older git binaries.
	out, err := runGit(path, "rev-parse", "--git-dir")
	if err != nil {
		return "", err
	}

	dir := strings.TrimSpace(out)
	if dir == "" {
		return "", fmt.Errorf("git rev-parse --git-dir returned empty output for %s", path)
	}
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(path, dir)
	}

	return filepath.Clean(dir), nil
}

// resolveWorkTree returns the working tree root for path, if any. Bare
// repositories (and anything else `git rev-parse --show-toplevel` can't
// resolve) report ok=false, matching how git.PlainOpen treats them (nil
// worktree filesystem).
func resolveWorkTree(path string) (string, bool) {
	out, err := runGit(path, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", false
	}

	top := strings.TrimSpace(out)
	if top == "" {
		return "", false
	}

	return top, true
}
