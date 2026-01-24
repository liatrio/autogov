package release

import (
	"fmt"
	"sort"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// OpenRepository opens a git repository at the given path
func OpenRepository(path string) (*git.Repository, error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open repository at %s: %w", path, err)
	}
	return repo, nil
}

// DiscoverLatestTag finds the most recent semver tag in the repository
// if firstParent is true, only considers tags that are ancestors of HEAD via first-parent
func DiscoverLatestTag(repo *git.Repository, firstParent bool) (*Version, string, error) {
	tags, err := repo.Tags()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get tags: %w", err)
	}

	var semverTags []*tagInfo
	err = tags.ForEach(func(ref *plumbing.Reference) error {
		tagName := ref.Name().Short()

		// try to parse as semver
		ver, err := ParseVersion(tagName)
		if err != nil {
			// skip non-semver tags
			return nil
		}

		semverTags = append(semverTags, &tagInfo{
			version: ver,
			name:    tagName,
			hash:    ref.Hash(),
		})
		return nil
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to iterate tags: %w", err)
	}

	if len(semverTags) == 0 {
		return nil, "", nil // no tags found
	}

	// if firstParent is requested, filter to tags that are ancestors of HEAD
	if firstParent {
		semverTags, err = filterAncestorTags(repo, semverTags)
		if err != nil {
			return nil, "", err
		}
		if len(semverTags) == 0 {
			return nil, "", nil
		}
	}

	// sort by version (descending)
	sort.Slice(semverTags, func(i, j int) bool {
		return !semverTags[i].version.LessThan(semverTags[j].version)
	})

	latest := semverTags[0]
	return latest.version, latest.name, nil
}

// tagInfo holds information about a tag
type tagInfo struct {
	version *Version
	name    string
	hash    plumbing.Hash
}

// filterAncestorTags filters tags to only those that are ancestors of HEAD
func filterAncestorTags(repo *git.Repository, tags []*tagInfo) ([]*tagInfo, error) {
	head, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("failed to get HEAD: %w", err)
	}

	headCommit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return nil, fmt.Errorf("failed to get HEAD commit: %w", err)
	}

	// build a set of ancestor hashes by walking first-parent only
	ancestors := make(map[plumbing.Hash]bool)
	current := headCommit
	for current != nil {
		ancestors[current.Hash] = true
		if current.NumParents() == 0 {
			break
		}
		// only follow first parent
		current, err = current.Parent(0)
		if err != nil {
			break
		}
	}

	// filter tags to those whose commit is in ancestors
	var filtered []*tagInfo
	for _, tag := range tags {
		// need to resolve tag to commit hash (could be lightweight or annotated)
		commitHash, err := resolveTagToCommit(repo, tag.hash)
		if err != nil {
			continue
		}
		if ancestors[commitHash] {
			filtered = append(filtered, tag)
		}
	}

	return filtered, nil
}

// resolveTagToCommit resolves a tag reference to its underlying commit hash
func resolveTagToCommit(repo *git.Repository, tagHash plumbing.Hash) (plumbing.Hash, error) {
	// try as annotated tag first
	tagObj, err := repo.TagObject(tagHash)
	if err == nil {
		// annotated tag - get the commit it points to
		commit, err := tagObj.Commit()
		if err != nil {
			return plumbing.ZeroHash, err
		}
		return commit.Hash, nil
	}

	// lightweight tag - hash is the commit hash directly
	_, err = repo.CommitObject(tagHash)
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("cannot resolve tag to commit: %w", err)
	}
	return tagHash, nil
}

// GetCommitsSinceTag returns all commits since the given tag (or from beginning if tagName is empty)
// if firstParent is true, only follows first parent in merge commits
// toRef specifies the target ref (defaults to HEAD if empty)
func GetCommitsSinceTag(repo *git.Repository, tagName string, toRef string, firstParent bool) ([]*object.Commit, error) {
	// resolve target ref
	var targetHash plumbing.Hash
	if toRef == "" || toRef == "HEAD" {
		head, err := repo.Head()
		if err != nil {
			return nil, fmt.Errorf("failed to get HEAD: %w", err)
		}
		targetHash = head.Hash()
	} else {
		resolved, err := resolveRef(repo, toRef)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve ref %s: %w", toRef, err)
		}
		targetHash = resolved
	}

	var stopHash plumbing.Hash
	if tagName != "" {
		// find the tag's commit
		tagRef, err := repo.Tag(tagName)
		if err != nil {
			return nil, fmt.Errorf("failed to find tag %s: %w", tagName, err)
		}
		stopHash, err = resolveTagToCommit(repo, tagRef.Hash())
		if err != nil {
			return nil, fmt.Errorf("failed to resolve tag %s: %w", tagName, err)
		}
	}

	if firstParent {
		return walkFirstParent(repo, targetHash, stopHash)
	}
	return walkAllParents(repo, targetHash, stopHash)
}

// resolveRef resolves a ref string to a commit hash
func resolveRef(repo *git.Repository, ref string) (plumbing.Hash, error) {
	// try as branch
	branchRef, err := repo.Reference(plumbing.NewBranchReferenceName(ref), true)
	if err == nil {
		return branchRef.Hash(), nil
	}

	// try as tag
	tagRef, err := repo.Tag(ref)
	if err == nil {
		return resolveTagToCommit(repo, tagRef.Hash())
	}

	// try as full commit hash (40 chars)
	if len(ref) == 40 {
		hash := plumbing.NewHash(ref)
		if _, err := repo.CommitObject(hash); err == nil {
			return hash, nil
		}
	}

	// try as short commit hash (7+ chars) - iterate to find match
	if len(ref) >= 7 && len(ref) < 40 {
		commitIter, err := repo.CommitObjects()
		if err == nil {
			var match plumbing.Hash
			matchCount := 0
			_ = commitIter.ForEach(func(c *object.Commit) error {
				if strings.HasPrefix(c.Hash.String(), ref) {
					match = c.Hash
					matchCount++
					if matchCount > 1 {
						return fmt.Errorf("ambiguous")
					}
				}
				return nil
			})
			if matchCount == 1 {
				return match, nil
			}
		}
	}

	return plumbing.ZeroHash, fmt.Errorf("cannot resolve ref: %s", ref)
}

// walkFirstParent walks commits following only first parent
func walkFirstParent(repo *git.Repository, startHash, stopHash plumbing.Hash) ([]*object.Commit, error) {
	var commits []*object.Commit
	current, err := repo.CommitObject(startHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get start commit: %w", err)
	}

	for current != nil {
		if stopHash != plumbing.ZeroHash && current.Hash == stopHash {
			break
		}

		commits = append(commits, current)

		if current.NumParents() == 0 {
			break
		}

		current, err = current.Parent(0)
		if err != nil {
			break
		}
	}

	return commits, nil
}

// walkAllParents walks all commits reachable from start (BFS traversal)
func walkAllParents(repo *git.Repository, startHash, stopHash plumbing.Hash) ([]*object.Commit, error) {
	var commits []*object.Commit
	seen := make(map[plumbing.Hash]bool)
	queue := []plumbing.Hash{startHash}

	for len(queue) > 0 {
		hash := queue[0]
		queue = queue[1:]

		if seen[hash] {
			continue
		}
		seen[hash] = true

		// stop at the tag commit (don't include it)
		if stopHash != plumbing.ZeroHash && hash == stopHash {
			continue
		}

		commit, err := repo.CommitObject(hash)
		if err != nil {
			continue
		}

		commits = append(commits, commit)

		// add all parents to queue
		for i := 0; i < commit.NumParents(); i++ {
			parent, err := commit.Parent(i)
			if err != nil {
				continue
			}
			if !seen[parent.Hash] {
				queue = append(queue, parent.Hash)
			}
		}
	}

	return commits, nil
}

// GetRepositoryName attempts to extract the repository name from remote URL
func GetRepositoryName(repo *git.Repository) string {
	remotes, err := repo.Remotes()
	if err != nil || len(remotes) == 0 {
		return "unknown"
	}

	// prefer "origin" remote
	for _, remote := range remotes {
		if remote.Config().Name == "origin" {
			urls := remote.Config().URLs
			if len(urls) > 0 {
				return parseRepoNameFromURL(urls[0])
			}
		}
	}

	// fallback to first remote
	urls := remotes[0].Config().URLs
	if len(urls) > 0 {
		return parseRepoNameFromURL(urls[0])
	}

	return "unknown"
}

// parseRepoNameFromURL extracts owner/repo from a git URL
// returns "unknown" if parsing fails to avoid leaking raw URLs
func parseRepoNameFromURL(url string) string {
	// handle ssh format: git@github.com:owner/repo.git
	if strings.HasPrefix(url, "git@") {
		parts := strings.Split(url, ":")
		if len(parts) == 2 {
			repoPath := strings.TrimSuffix(parts[1], ".git")
			// validate it looks like owner/repo
			if strings.Contains(repoPath, "/") && !strings.Contains(repoPath, "@") {
				return repoPath
			}
		}
		return "unknown"
	}

	// handle https format: https://github.com/owner/repo.git
	url = strings.TrimSuffix(url, ".git")
	parts := strings.Split(url, "/")
	if len(parts) >= 2 {
		owner := parts[len(parts)-2]
		repo := parts[len(parts)-1]
		// validate no credentials in path
		if !strings.Contains(owner, "@") && !strings.Contains(repo, "@") &&
			!strings.Contains(owner, ":") && !strings.Contains(repo, ":") {
			return owner + "/" + repo
		}
	}

	return "unknown"
}
