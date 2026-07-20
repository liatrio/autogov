package predicate

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	gh "github.com/google/go-github/v89/github"
	ghclient "github.com/liatrio/autogov/pkg/github"
)

// SourceReviewPredicateTypeURI is the custom autogov source-review predicate
// type. It records the human PR-review/approval evidence for the source
// revision that produced an artifact (SLSA source-track / two-person review).
// No in-toto or SLSA standard predicate exists for source review — SLSA's
// source track leaves it vendor-specific and gittuf/liatr.io both namespace
// their own — so this mirrors the metadata/code-scan precedent.
//
// v0.2 (current, only recognized version): adds fail-closed continuity evidence
// (continuityComplete + continuityEvidence) so continuityStartRevision becomes a
// genuine no-gap CLAIM rather than a placeholder. The bump to a NEW URI was
// deliberate: it stops an OLD (v0.1) verifier — which has no notion of
// continuityComplete — from misreading a v0.2 bundle's now-populated
// continuityStartRevision as a satisfied L3 continuity leg (an over-claim). v0.1
// is no longer recognized; a missing continuityComplete still decodes false
// (dormant), so a v0.2 verifier can never over-claim L3 from an older bundle.
const SourceReviewPredicateTypeURI = "https://autogov.dev/attestation/source-review/v0.2"

// GitHub pull request review states (REST Reviews endpoint). The real enum is
// CHANGES_REQUESTED (not the docs' "REQUEST_CHANGES"). COMMENTED and PENDING are
// non-opinionated and ignored.
const (
	reviewStateApproved         = "APPROVED"
	reviewStateChangesRequested = "CHANGES_REQUESTED"
	reviewStateDismissed        = "DISMISSED"
)

// userTypeBot is the User.Type value for GitHub App bot accounts. Note it does
// NOT catch a machine/service account typed "User"; association is the
// orthogonal signal for those (carried per-approver for a future min_association
// knob).
const userTypeBot = "Bot"

// caps that bound untrusted GitHub free-text in a signed, public attestation.
// Prefixed sr* to avoid colliding with the code-scan caps in the same package.
const (
	srMaxStringLen    = 512  // login, url, repo, ref
	srMaxSHALen       = 64   // commit SHAs (sha-1 40, sha-256 64)
	srMaxTimestampLen = 64   // RFC3339
	srMaxApprovers    = 1000 // backstop; distinct human approvers never approach this
	srMaxControlItems = 1000 // backstop for status-check contexts + bypass actors (matches schema maxItems)
)

// SourceReviewPR captures the pull request whose merge produced the source
// revision. Omitted entirely when no merged PR is resolved.
type SourceReviewPR struct {
	Number         int    `json:"number"`
	URL            string `json:"url,omitempty"`
	Author         string `json:"author,omitempty"`
	MergedAt       string `json:"mergedAt,omitempty"`
	MergeCommitSha string `json:"mergeCommitSha,omitempty"`
}

// SourceReviewApprover is one distinct reviewer whose latest opinionated review
// state is APPROVED (the PR author is never included). stale and isBot are
// recorded so the gate can recompute/verify the count rather than trust a
// producer-asserted summary boolean.
type SourceReviewApprover struct {
	Login       string `json:"login"`
	Association string `json:"association,omitempty"`
	SubmittedAt string `json:"submittedAt,omitempty"`
	CommitID    string `json:"commitId,omitempty"`
	Stale       bool   `json:"stale"`
	IsBot       bool   `json:"isBot"`
}

// SourceReviewSummary is always populated, even when approvers[] is omitted, so
// an operator can gate without the approver list. The booleans are EVIDENCE,
// never gate inputs: pass/fail derives only from the numeric counts (see the
// gating policy). distinctApprovers is the STRICTEST count (author, stale,
// dismissed, changes-requested, and bot reviewers excluded).
type SourceReviewSummary struct {
	Approvals            int  `json:"approvals"`
	DistinctApprovers    int  `json:"distinctApprovers"`
	ChangesRequested     int  `json:"changesRequested"`
	RequiredApprovals    int  `json:"requiredApprovals"`
	RequirementMet       bool `json:"requirementMet"`
	SelfApprovalExcluded bool `json:"selfApprovalExcluded"`
	// CodeownerReviewMet is tri-state: a nil pointer (JSON null) means "not
	// authoritatively determinable" — REST-only cannot reliably evaluate
	// CODEOWNERS, so the producer always leaves it null. The gate treats null as
	// undetermined and fails closed when codeowner review is required.
	CodeownerReviewMet *bool `json:"codeownerReviewMet"`
}

// SourceReviewBranchProtection records the review controls discovered on the
// target branch (best-effort; omitted when none is visible). Evidence for the
// required count; the gate bars on its own configured min_approvals.
type SourceReviewBranchProtection struct {
	RequireReviews               bool `json:"requireReviews"`
	RequiredApprovingReviewCount int  `json:"requiredApprovingReviewCount"`
	DismissStaleReviews          bool `json:"dismissStaleReviews"`
	RequireCodeownerReview       bool `json:"requireCodeownerReview"`
	// RequireLastPushApproval records GitHub's "last push must be approved by
	// someone other than the pusher" control. The producer enforces the
	// on-head-commit half via staleness (an approval not on the PR head does not
	// count); the "approver != last pusher" nuance requires push authorship not
	// fetched here, so it is recorded as evidence and left for a future version.
	RequireLastPushApproval bool `json:"requireLastPushApproval"`
}

// SourceReviewTechnicalControls records the enforced branch-protection technical
// controls (SLSA Source L3 evidence) discovered on the target branch via the
// repository ruleset (best-effort; omitted when none is visible). It is EVIDENCE
// ONLY: the producer records what is configured and never judges "disabled vs
// declared" — that is the verifier's/policy's job. The bool controls + status
// checks come from the no-admin ListRulesForBranch path; bypassActors require
// Administration:read (GetRuleset) and are simply omitted when that is denied.
type SourceReviewTechnicalControls struct {
	ForcePushBlocked      bool     `json:"forcePushBlocked"`
	RequiredLinearHistory bool     `json:"requiredLinearHistory"`
	DeletionBlocked       bool     `json:"deletionBlocked"`
	RequiredSignatures    bool     `json:"requiredSignatures"`
	RequiredStatusChecks  []string `json:"requiredStatusChecks,omitempty"`
	// BypassActors is the factual list of ruleset bypass actors, formatted
	// "<ActorType>:<ActorID>:<BypassMode>" (e.g. "Integration:801323:always"),
	// de-duped and sorted. The verifier judges narrow-vs-open. Read alongside
	// BypassActorsComplete: an empty list is only meaningful when complete.
	BypassActors []string `json:"bypassActors,omitempty"`
	// BypassActorsComplete is true only when the bypass-actor list is
	// AUTHORITATIVE: rule discovery was not truncated AND every backing ruleset's
	// bypass actors were readable (Administration:read granted). When false, an
	// empty BypassActors means "unknown", NOT "none" — the verifier MUST fail
	// closed rather than read the absence as no-bypass.
	BypassActorsComplete bool `json:"bypassActorsComplete"`
	// ContinuityComplete is true ONLY when the ruleset version-history walk proved
	// the L3-relevant controls were never disabled/weakened from a start revision
	// through the attested revision (an unbroken enforcement window). It is the
	// continuity sibling of BypassActorsComplete: when false (the default, and the
	// outcome of any unreadable/ambiguous history), the verifier MUST treat
	// continuity as UNDETERMINED and keep the source level dormant — an empty or
	// even populated ContinuityStartRevision is meaningless without it.
	ContinuityComplete bool `json:"continuityComplete"`
}

// SourceReviewContinuityEvidence records HOW continuity was established (or why it
// could not be), as audit evidence. It never relaxes a gate: the verifier keys on
// TechnicalControls.ContinuityComplete + a non-empty ContinuityStartRevision, not
// on this block. Method is "ruleset-history" on a proven window, else "none".
type SourceReviewContinuityEvidence struct {
	// Method is "ruleset-history" when continuity was proven by walking ruleset
	// version history, or "none" when it could not be established (the fail-closed
	// default). Any other meaning is reserved.
	Method string `json:"method"`
	// RulesetIDs are the distinct backing ruleset ids whose histories were walked.
	RulesetIDs []int64 `json:"rulesetIds,omitempty"`
	// VersionsWalked is the total number of historical ruleset versions inspected.
	VersionsWalked int `json:"versionsWalked"`
	// EarliestHistoryAt is the UpdatedAt of the oldest retained version observed
	// across the walked rulesets (RFC3339, UTC). Used to detect retention capping.
	EarliestHistoryAt string `json:"earliestHistoryAt,omitempty"`
	// WindowStartAt is the latest per-ruleset clean-run start across all legs
	// (RFC3339, UTC) — continuity holds only since ALL legs were simultaneously
	// enforced. Empty when continuity was not established.
	WindowStartAt string `json:"windowStartAt,omitempty"`
	// WeakenedAt is the UpdatedAt (RFC3339, UTC) of the version that broke
	// continuity (disabled/weakened/excluded/wide-bypass). Empty ("") on a clean
	// window.
	WeakenedAt string `json:"weakenedAt,omitempty"`
	// HistoryComplete is true only when every walked ruleset's history was read in
	// full (no 403/404, no pagination/truncation). False forces ContinuityComplete
	// false (unknown history is not "no changes").
	HistoryComplete bool `json:"historyComplete"`
	// RetentionCapped is true when the earliest retained version is NEWER than the
	// computed window start — the start cannot be corroborated by retained history,
	// so continuity fails closed.
	RetentionCapped bool `json:"retentionCapped"`
}

// SourceReview is the predicate portion of an autogov source-review attestation
// (https://autogov.dev/attestation/source-review/v0.2).
type SourceReview struct {
	// subject-binding fields, not part of the predicate body
	Type        ArtifactType `json:"-"`
	SubjectName string       `json:"-"`
	SubjectPath string       `json:"-"`
	Digest      string       `json:"-"`

	SourceRepository string          `json:"sourceRepository"`
	SourceRevision   string          `json:"sourceRevision"`
	Ref              string          `json:"ref,omitempty"`
	PullRequest      *SourceReviewPR `json:"pullRequest,omitempty"`

	Summary SourceReviewSummary `json:"summary"`

	// ApproversIncluded is true when approvers[] is authoritative (every
	// qualifying reviewer is present). The gate may recompute over approvers[]
	// only when this is true; otherwise it must use the summary counts and fail
	// closed if a per-reviewer filter it cannot satisfy is requested.
	ApproversIncluded bool                   `json:"approversIncluded"`
	Approvers         []SourceReviewApprover `json:"approvers,omitempty"`

	BranchProtection *SourceReviewBranchProtection `json:"branchProtection,omitempty"`

	// TechnicalControls records the enforced SLSA-L3 branch-protection controls
	// (force-push blocked, linear history, deletion blocked, required signatures,
	// required status checks, bypass actors). Best-effort, evidence only.
	TechnicalControls *SourceReviewTechnicalControls `json:"technicalControls,omitempty"`

	// ContinuityStartRevision is set ONLY when ContinuityEvidence proves an
	// unbroken enforcement window from this revision through the attested revision
	// (SLSA L3 continuity); it is empty otherwise. The verifier MUST NOT infer L3
	// continuity from this value alone — it gates on TechnicalControls.
	// ContinuityComplete AND a non-empty value together (absence or an
	// incomplete-proof value is undetermined, not satisfied).
	ContinuityStartRevision string `json:"continuityStartRevision,omitempty"`

	// ContinuityEvidence records how the continuity window was established (or why
	// it could not be). Audit evidence only — the gate keys on ContinuityComplete +
	// ContinuityStartRevision. Omitted when continuity was not even attempted.
	ContinuityEvidence *SourceReviewContinuityEvidence `json:"continuityEvidence,omitempty"`

	// ReviewDecision is reserved for an optional best-effort GraphQL enrichment
	// (pullRequest.reviewDecision). It is INFORMATIONAL ONLY and never a basis for
	// PASS. The producer adds no GraphQL client, so it is always empty here.
	ReviewDecision string `json:"reviewDecision,omitempty"`

	Configuration []ResourceDescriptor `json:"configuration"`

	// ReviewToolingComplete is false when the review evidence could not be fully
	// gathered (PRs/reviews unfetchable, or no merged PR resolved — which covers
	// both a genuine direct push and the ListPullRequestsWithCommit default-branch
	// quirk). Mirrors code-scan's invocation.executionSuccessful: the gate fails
	// this closed by default.
	ReviewToolingComplete bool `json:"reviewToolingComplete"`
}

// SourceReviewOptions contains options for creating a source-review predicate.
type SourceReviewOptions struct {
	Type             ArtifactType
	SubjectName      string
	SubjectPath      string
	Digest           string
	Owner            string
	Repo             string
	CommitSHA        string // the canonical source revision (merge/squash commit on the target branch)
	Ref              string // target branch ref of the artifact build
	PRNumber         int    // optional disambiguation hint; 0 = auto-discover from the commit
	IncludeApprovers bool   // default on; embeds the per-approver list
	ConfigURI        string
}

// NewSourceReview builds a source-review predicate from GitHub review evidence,
// implementing the locked review algorithm + GATE SEMANTICS. svc is injected for
// testability.
func NewSourceReview(ctx context.Context, svc ReviewService, opts SourceReviewOptions) (*SourceReview, error) {
	if opts.Owner == "" || opts.Repo == "" {
		return nil, fmt.Errorf("owner and repo are required")
	}
	commitSHA := strings.TrimSpace(opts.CommitSHA)
	if commitSHA == "" {
		return nil, fmt.Errorf("commit SHA is required")
	}

	queriedSHA := truncateRunes(commitSHA, srMaxSHALen)

	c := &SourceReview{
		Type:                  opts.Type,
		SubjectName:           opts.SubjectName,
		SubjectPath:           opts.SubjectPath,
		Digest:                opts.Digest,
		SourceRepository:      truncateRunes(fmt.Sprintf("https://github.com/%s/%s", opts.Owner, opts.Repo), srMaxStringLen),
		SourceRevision:        queriedSHA,
		Ref:                   truncateRunes(normalizeRef(opts.Ref), srMaxStringLen),
		Configuration:         []ResourceDescriptor{},
		ApproversIncluded:     opts.IncludeApprovers,
		ReviewToolingComplete: true,
	}
	if opts.ConfigURI != "" {
		c.Configuration = append(c.Configuration, ResourceDescriptor{URI: truncateRunes(opts.ConfigURI, srMaxStringLen)})
	}

	// step 1: resolve the PR whose merge produced the queried source revision.
	prs, err := listPRsWithCommit(ctx, svc, opts.Owner, opts.Repo, queriedSHA)
	if err != nil {
		// cannot enumerate PRs -> blind -> incompleteness (fail closed downstream).
		c.ReviewToolingComplete = false
		return c, nil
	}

	selected := selectMergedPR(prs, queriedSHA, opts.PRNumber)
	if selected == nil {
		// No merged PR matched. EITHER a genuine unreviewed direct push OR the
		// documented ListPullRequestsWithCommit default-branch quirk (a
		// release-branch/tag build whose SHA is not on the default branch returns
		// ONLY open PRs). REST cannot cheaply distinguish the two, so we mirror
		// code-scan's incomplete-vs-definitive handling and treat it as
		// incompleteness rather than a false hard fail. The gate fails this closed
		// by default (fail_on_incomplete_review), so an unreviewed direct push is
		// still rejected without spuriously failing legitimate release builds.
		c.ReviewToolingComplete = false
		return c, nil
	}

	prAuthorID := selected.GetUser().GetID()
	prHeadSHA := selected.GetHead().GetSHA()
	prBaseRef := selected.GetBase().GetRef()
	if c.Ref == "" {
		c.Ref = truncateRunes(prBaseRef, srMaxStringLen)
	}
	c.PullRequest = &SourceReviewPR{
		Number:         selected.GetNumber(),
		URL:            truncateRunes(selected.GetHTMLURL(), srMaxStringLen),
		Author:         truncateRunes(selected.GetUser().GetLogin(), srMaxStringLen),
		MergedAt:       formatTimestamp(selected.GetMergedAt()),
		MergeCommitSha: truncateRunes(selected.GetMergeCommitSHA(), srMaxSHALen),
	}

	// We cannot proceed safely without the PR author id (to exclude self-approval)
	// or the PR head SHA (to judge staleness). A nil author would make prAuthorID 0
	// and silently fail the self-approval exclusion (a real reviewer's id never
	// equals 0), so a solo author could otherwise clear the gate; an empty head SHA
	// would make every approval look fresh. Fail closed as incompleteness instead.
	if selected.GetUser() == nil || prAuthorID == 0 || prHeadSHA == "" {
		c.ReviewToolingComplete = false
		return c, nil
	}

	// step 8 (fetched before staleness in step 4, which needs dismissStale):
	// branch protection + rulesets are best-effort. A 404 / no-admin just leaves
	// the threshold unknown; it does NOT make the result incomplete, because the
	// gate bars on its own min_approvals, not on requiredApprovals (evidence only).
	dismissStale, requiredApprovals, bp := fetchReviewControls(ctx, svc, opts.Owner, opts.Repo, prBaseRef)
	if bp != nil {
		c.BranchProtection = bp
	}

	// step 8b: enforced SLSA-L3 technical controls (force-push/linear/deletion/
	// signatures/status-checks + bypass actors). Best-effort, evidence only; the
	// verifier (not the producer) judges whether they earn L3.
	tc, idSet := fetchTechnicalControls(ctx, svc, opts.Owner, opts.Repo, prBaseRef)
	if tc != nil {
		c.TechnicalControls = tc

		// step 8c (v0.2): prove the L3-relevant controls were never disabled or
		// weakened from a start revision through the attested revision by walking
		// the ruleset VERSION HISTORY. FAIL-CLOSED on any unreadable history,
		// non-active version, branch-exclusion, wide bypass, truncation, retention
		// cap, or commit-walk truncation: ContinuityComplete stays false and
		// ContinuityStartRevision stays empty so the verifier keeps L3 dormant.
		startRev, complete, ev := computeContinuity(ctx, svc, opts.Owner, opts.Repo, normalizeRef(prBaseRef), idSet, queriedSHA)
		tc.ContinuityComplete = complete
		c.ContinuityStartRevision = truncateRunes(startRev, srMaxSHALen)
		c.ContinuityEvidence = &ev
	}

	// step 2: reviews -> latest opinionated review per user.id.
	reviews, err := listReviews(ctx, svc, opts.Owner, opts.Repo, selected.GetNumber())
	if err != nil {
		// we have the PR but cannot read its reviews -> blind on the core evidence.
		c.ReviewToolingComplete = false
		return c, nil
	}
	latest := latestOpinionatedPerUser(reviews)

	// steps 3-6: classify each reviewer's latest opinionated state.
	var approvers []SourceReviewApprover
	changesRequested := 0
	selfApproved := false
	for _, r := range latest {
		uid := r.GetUser().GetID()
		state := strings.ToUpper(r.GetState())
		// step 3: the PR author's own review is never counted — a self-approval
		// cannot satisfy the gate, and a self CHANGES_REQUESTED cannot block it
		// (both are dropped here, before the approver/changes-requested tallies).
		if uid == prAuthorID {
			if state == reviewStateApproved {
				selfApproved = true
			}
			continue
		}
		isBot := r.GetUser().GetType() == userTypeBot
		switch state {
		case reviewStateApproved:
			// step 4: staleness. When the branch does NOT dismiss stale reviews, an
			// approval on a commit other than the PR head is stale. NEVER compare
			// commit_id to the artifact's source revision — for squash/rebase merges
			// they always differ (false stale). Compare to the PR head SHA only. An
			// absent commit_id cannot be confirmed to be on the head, so it is treated
			// as stale (fail closed) rather than as a fresh approval.
			stale := !dismissStale && r.GetCommitID() != prHeadSHA
			approvers = append(approvers, SourceReviewApprover{
				Login:       truncateRunes(r.GetUser().GetLogin(), srMaxStringLen),
				Association: normalizeAssociation(r.GetAuthorAssociation()),
				SubmittedAt: formatTimestamp(r.GetSubmittedAt()),
				CommitID:    truncateRunes(r.GetCommitID(), srMaxSHALen),
				Stale:       stale,
				IsBot:       isBot,
			})
		case reviewStateChangesRequested:
			// GATE SEMANTICS (a): an outstanding CHANGES_REQUESTED blocks regardless
			// of approval count. Counted after the self/bot reduction; a later
			// DISMISSED clears it (handled by the latest-state reduction). Staleness
			// is intentionally NOT applied — a standing change request blocks even
			// after head movement (GitHub keeps it blocking until dismissed).
			if !isBot {
				changesRequested++
			}
		case reviewStateDismissed:
			// step 5: DISMISSED never counts and never resurrects an earlier APPROVED.
		}
	}

	// deterministic order for a reproducible signed artifact. The cap is a DoS
	// backstop (real PRs never approach it); the distinct count below is computed
	// AFTER truncation, so summary.distinctApprovers and approvers[] stay
	// consistent and any truncation undercounts (fail-closed).
	sortApprovers(approvers)
	if len(approvers) > srMaxApprovers {
		approvers = approvers[:srMaxApprovers]
	}

	// step 7 / GATE SEMANTICS (b): the producer ALWAYS computes distinctApprovers
	// at the STRICTEST filtering (author, stale, dismissed, changes-requested, and
	// bot reviewers excluded). There are no producer-side loosening knobs; the
	// policy can only tighten this further, never loosen it.
	distinct := 0
	for _, a := range approvers {
		if !a.Stale && !a.IsBot {
			distinct++
		}
	}

	c.Summary = SourceReviewSummary{
		Approvals:            len(approvers),
		DistinctApprovers:    distinct,
		ChangesRequested:     changesRequested,
		RequiredApprovals:    requiredApprovals,
		RequirementMet:       distinct >= requiredApprovals,
		SelfApprovalExcluded: selfApproved,
		CodeownerReviewMet:   nil, // tri-state null (REST-only; no CODEOWNERS authority)
	}
	if opts.IncludeApprovers {
		if approvers == nil {
			approvers = []SourceReviewApprover{}
		}
		c.Approvers = approvers
	}

	return c, nil
}

// listPRsWithCommit paginates ListPullRequestsWithCommit for a SHA.
func listPRsWithCommit(ctx context.Context, svc ReviewService, owner, repo, sha string) ([]*gh.PullRequest, error) {
	const maxPages = 10
	opts := &gh.ListOptions{PerPage: 100}
	var all []*gh.PullRequest
	for attempt := 0; attempt < maxPages; attempt++ {
		prs, resp, err := svc.ListPullRequestsWithCommit(ctx, owner, repo, sha, opts)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err != nil {
			return nil, fmt.Errorf("failed to list pull requests for commit %s: %w", sha, err)
		}
		all = append(all, prs...)
		if resp == nil || resp.NextPage == 0 {
			break
		}
		if attempt == maxPages-1 {
			return nil, fmt.Errorf("pull request pagination exceeded %d pages", maxPages)
		}
		opts.Page = resp.NextPage
	}
	return all, nil
}

// selectMergedPR picks the pull request whose merge produced the queried SHA.
// The merge_commit_sha == queried-SHA binding (plus a non-zero mergedAt) is
// MANDATORY on every path: it is what ties the captured reviews to the attested
// sourceRevision (works for merge, squash, and rebase merges). prNumber is only a
// disambiguator among PRs that already match — never an override, so a caller
// cannot bind a well-reviewed PR's approvals to an arbitrary/unreviewed commit.
func selectMergedPR(prs []*gh.PullRequest, sha string, prNumber int) *gh.PullRequest {
	for _, p := range prs {
		if p == nil {
			continue
		}
		if p.GetMergeCommitSHA() != sha || p.GetMergedAt().IsZero() {
			continue
		}
		if prNumber > 0 && p.GetNumber() != prNumber {
			continue
		}
		return p
	}
	return nil
}

// fetchReviewControls reads the review controls on the target branch from
// classic branch protection (needs admin) and rulesets (no admin), best-effort.
// Returns whether stale reviews are dismissed, the required approving-review
// count (max of both sources), and the discovered controls (nil when none).
func fetchReviewControls(ctx context.Context, svc ReviewService, owner, repo, branch string) (bool, int, *SourceReviewBranchProtection) {
	if branch == "" {
		return false, 0, nil
	}

	var bpCount, rsCount int
	dismissStale := false
	requireReviews := false
	requireCodeowner := false
	requireLastPush := false
	have := false

	prot, resp, err := svc.GetBranchProtection(ctx, owner, repo, branch)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil && prot != nil {
		if rpr := prot.GetRequiredPullRequestReviews(); rpr != nil {
			have = true
			requireReviews = true
			bpCount = rpr.RequiredApprovingReviewCount
			if rpr.DismissStaleReviews {
				dismissStale = true
			}
			if rpr.RequireCodeOwnerReviews {
				requireCodeowner = true
			}
			if rpr.RequireLastPushApproval {
				requireLastPush = true
			}
		}
	}

	for _, r := range listPullRequestRules(ctx, svc, owner, repo, branch) {
		if r == nil {
			continue
		}
		have = true
		requireReviews = true
		p := r.GetParameters()
		if p.RequiredApprovingReviewCount > rsCount {
			rsCount = p.RequiredApprovingReviewCount
		}
		if p.DismissStaleReviewsOnPush {
			dismissStale = true
		}
		if p.RequireCodeOwnerReview {
			requireCodeowner = true
		}
		if p.RequireLastPushApproval {
			requireLastPush = true
		}
	}

	required := max(bpCount, rsCount)
	if !have {
		return dismissStale, required, nil
	}
	return dismissStale, required, &SourceReviewBranchProtection{
		RequireReviews:               requireReviews,
		RequiredApprovingReviewCount: required,
		DismissStaleReviews:          dismissStale,
		RequireCodeownerReview:       requireCodeowner,
		RequireLastPushApproval:      requireLastPush,
	}
}

// listPullRequestRules paginates ListRulesForBranch and returns the pull_request
// branch rules across all pages (best-effort: stops on the first error with
// whatever was collected, since rulesets only feed evidence-only thresholds).
func listPullRequestRules(ctx context.Context, svc ReviewService, owner, repo, branch string) []*gh.PullRequestBranchRule {
	const maxPages = 10
	opts := &gh.ListOptions{PerPage: 100}
	var all []*gh.PullRequestBranchRule
	for attempt := 0; attempt < maxPages; attempt++ {
		rules, resp, err := svc.ListRulesForBranch(ctx, owner, repo, branch, opts)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err != nil || rules == nil {
			break
		}
		all = append(all, rules.PullRequest...)
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return all
}

// fetchTechnicalControls reads the enforced SLSA-L3 branch-protection technical
// controls on the target branch from the repository ruleset. Best-effort and
// evidence-only (matching fetchReviewControls): the rule-type presence + status
// checks come from the no-admin, PAGINATED ListRulesForBranch path; bypass actors
// require Administration:read via GetRuleset and are omitted (not fatal) when
// denied. A producer error here never blocks the attestation — the gate fails
// closed, the producer does not. Returns nil when no ruleset control is visible.
//
// ListRulesForBranch returns the rules ACTIVE for the branch (active rulesets),
// so rule-type presence is a faithful proxy for the control being enforced.
//
// Rule discovery is paginated and bypass actors are unioned across EVERY distinct
// backing ruleset, because under-reading a bypass actor would make the repo look
// more locked than it is (an over-claim). BypassActorsComplete records whether
// the bypass list is authoritative: it is false when pagination was truncated OR
// any GetRuleset failed, so the verifier can fail closed on "unknown".
//
// It also returns the distinct backing ruleset idSet so computeContinuity can
// walk each ruleset's version history. The idSet is nil/empty when no controls
// were discovered (tc==nil), which makes continuity fail closed.
func fetchTechnicalControls(ctx context.Context, svc ReviewService, owner, repo, branch string) (*SourceReviewTechnicalControls, map[int64]struct{}) {
	if branch == "" {
		return nil, nil
	}

	const maxPages = 10
	tc := &SourceReviewTechnicalControls{}
	idSet := map[int64]struct{}{}
	seenCtx := map[string]struct{}{}
	addID := func(id int64) {
		if id > 0 {
			idSet[id] = struct{}{}
		}
	}

	opts := &gh.ListOptions{PerPage: 100}
	sawRules := false
	rulesComplete := true
	for attempt := 0; attempt < maxPages; attempt++ {
		rules, resp, err := svc.ListRulesForBranch(ctx, owner, repo, branch, opts)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err != nil || rules == nil {
			if !sawRules {
				return nil, nil // read nothing at all -> no controls visible.
			}
			rulesComplete = false // partial read -> bypass list is not authoritative.
			break
		}
		sawRules = true

		// rule-type presence (OR across pages).
		tc.ForcePushBlocked = tc.ForcePushBlocked || len(rules.NonFastForward) > 0
		tc.RequiredLinearHistory = tc.RequiredLinearHistory || len(rules.RequiredLinearHistory) > 0
		tc.DeletionBlocked = tc.DeletionBlocked || len(rules.Deletion) > 0
		tc.RequiredSignatures = tc.RequiredSignatures || len(rules.RequiredSignatures) > 0

		// required status-check contexts (de-duped; sorted once at the end).
		for _, rsc := range rules.RequiredStatusChecks {
			if rsc == nil {
				continue
			}
			for _, c := range rsc.Parameters.RequiredStatusChecks {
				if c == nil {
					continue
				}
				ctxStr := truncateRunes(c.GetContext(), srMaxStringLen)
				if ctxStr == "" {
					continue
				}
				if _, dup := seenCtx[ctxStr]; !dup {
					seenCtx[ctxStr] = struct{}{}
					tc.RequiredStatusChecks = append(tc.RequiredStatusChecks, ctxStr)
				}
			}
		}

		// distinct rulesets backing the observed rules (different rule types can
		// come from different — incl. org-level — rulesets).
		for _, m := range rules.NonFastForward {
			if m != nil {
				addID(m.GetRulesetID())
			}
		}
		for _, m := range rules.RequiredLinearHistory {
			if m != nil {
				addID(m.GetRulesetID())
			}
		}
		for _, m := range rules.Deletion {
			if m != nil {
				addID(m.GetRulesetID())
			}
		}
		for _, m := range rules.RequiredSignatures {
			if m != nil {
				addID(m.GetRulesetID())
			}
		}
		for _, r := range rules.RequiredStatusChecks {
			if r != nil {
				addID(r.GetRulesetID())
			}
		}
		for _, r := range rules.PullRequest {
			if r != nil {
				addID(r.GetRulesetID())
			}
		}

		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
		if attempt == maxPages-1 {
			rulesComplete = false // more pages remain but we hit the cap.
		}
	}

	if !sawRules {
		return nil, nil
	}
	sort.Strings(tc.RequiredStatusChecks)
	if len(tc.RequiredStatusChecks) > srMaxControlItems {
		tc.RequiredStatusChecks = tc.RequiredStatusChecks[:srMaxControlItems] // DoS backstop; never blocks the attestation.
	}

	// bypass actors over the distinct backing rulesets. includesParents=true
	// resolves org/enterprise parent rulesets through the repo-scoped endpoint.
	// The list is authoritative only if rule discovery was complete AND every
	// GetRuleset succeeded — otherwise BypassActorsComplete is false so the
	// verifier fails closed instead of reading an empty list as "no bypass".
	bypassComplete := rulesComplete
	seenActor := map[string]struct{}{}
	for id := range idSet {
		rs, rsResp, rsErr := svc.GetRuleset(ctx, owner, repo, id, true)
		if rsResp != nil {
			_ = rsResp.Body.Close()
		}
		if rsErr != nil || rs == nil {
			bypassComplete = false // denied/unreadable: keep other controls, mark incomplete.
			continue
		}
		for _, a := range rs.GetBypassActors() {
			if a == nil {
				continue
			}
			s := formatBypassActor(a)
			if _, dup := seenActor[s]; !dup {
				seenActor[s] = struct{}{}
				tc.BypassActors = append(tc.BypassActors, s)
			}
		}
	}
	sort.Strings(tc.BypassActors)
	if len(tc.BypassActors) > srMaxControlItems {
		tc.BypassActors = tc.BypassActors[:srMaxControlItems] // DoS backstop
		bypassComplete = false                                // truncated -> not authoritative.
	}
	tc.BypassActorsComplete = bypassComplete

	// keep omitempty honest: emit only when a control was actually discovered.
	if !tc.ForcePushBlocked && !tc.RequiredLinearHistory && !tc.DeletionBlocked &&
		!tc.RequiredSignatures && len(tc.RequiredStatusChecks) == 0 && len(tc.BypassActors) == 0 {
		return nil, nil
	}
	return tc, idSet
}

// continuityMaxVersions caps the per-ruleset history pages/versions walked, a DoS
// backstop. Hitting it makes HistoryComplete false (fail closed) — we will not
// claim continuity over a history we could not read in full.
const (
	continuityMaxHistoryPages = 20
	continuityMaxVersions     = 2000
)

// computeContinuity proves, FAIL-CLOSED, that the L3-relevant controls were never
// disabled or weakened from a start revision through the attested revision, by
// walking each backing ruleset's VERSION HISTORY (newest->oldest). It returns the
// start revision + complete=true ONLY when an unbroken clean window is proven and
// corroborated; on ANY ambiguity it returns ("", false, ev{Method:"none"}).
//
// created_at is NOT load-bearing: each version's full STATE is inspected. The
// verifier never calls GitHub — all GitHub/time->commit work happens here.
//
// Fail-closed conditions (each yields ("", false, ...)):
//   - history 403/404/unreadable (incl. the org/parent fallback) -> HistoryComplete false
//   - pagination/version cap hit (history truncation)            -> HistoryComplete false
//   - the current bypass list is not authoritative               -> can't bound "narrow"
//   - any version: enforcement != "active"                       -> WeakenedAt set
//   - any version: a required L3 rule type absent                -> WeakenedAt set
//   - any version: conditions.ref_name does not target branch    -> WeakenedAt set
//     (incl. an explicit branch EXCLUSION window)
//   - any version: a bypass actor NOT in the current narrow set  -> WeakenedAt set
//   - earliest retained version newer than the window start      -> RetentionCapped
//   - the time->commit walk truncates / errors                  -> fail closed
func computeContinuity(ctx context.Context, svc ReviewService, owner, repo, branch string, idSet map[int64]struct{}, queriedSHA string) (string, bool, SourceReviewContinuityEvidence) {
	none := SourceReviewContinuityEvidence{Method: continuityMethodNone}

	if len(idSet) == 0 || branch == "" {
		return "", false, none // no backing rulesets -> undetermined.
	}

	// The "narrow" bound for history is the CURRENT attested bypass set: a clean
	// version may not have had ANY bypass actor wider than what is enforced now. We
	// also capture each ruleset's CreatedAt to corroborate that the oldest retained
	// version is the ruleset's creation (retention-cap detection). If the current
	// set is not authoritative we cannot bound narrowness -> fail closed.
	current, createdAt, currentComplete := currentRulesetFacts(ctx, svc, owner, repo, idSet)
	if !currentComplete {
		return "", false, none
	}

	// The repo default branch: needed to safely judge a version that targets only
	// "~DEFAULT_BRANCH". Unreadable -> defaultBranch == "" -> a "~DEFAULT_BRANCH"-only
	// version fails closed (cannot prove it covered this branch).
	defaultBranch := repoDefaultBranch(ctx, svc, owner, repo)

	ev := SourceReviewContinuityEvidence{
		Method:          continuityMethodHistory,
		HistoryComplete: true,
	}
	ids := make([]int64, 0, len(idSet))
	for id := range idSet {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	ev.RulesetIDs = ids

	var latestStart time.Time // max over legs: continuity holds only since ALL enforced.
	var earliestRetained time.Time
	for _, id := range ids {
		versions, ok := walkRulesetHistory(ctx, svc, owner, repo, id, &ev)
		if !ok {
			return "", false, none // unreadable/truncated history -> fail closed.
		}
		if len(versions) == 0 {
			return "", false, none // no version state -> undetermined.
		}

		// versions are newest->oldest; the oldest retained sets earliest history.
		oldest := versions[len(versions)-1]
		if oldest.updatedAt.IsZero() {
			// a retained version with no effective time cannot anchor a window or be
			// corroborated against creation -> fail closed.
			return "", false, none
		}
		if earliestRetained.IsZero() || oldest.updatedAt.Before(earliestRetained) {
			earliestRetained = oldest.updatedAt
		}

		legStart, weakenedAt, brokeObserved, run, clean := legCleanStart(versions, branch, defaultBranch, current)
		if !clean {
			ev.WeakenedAt = formatContinuityTime(weakenedAt)
			return "", false, ev
		}
		if legStart.IsZero() {
			// a clean run whose start time is zero (a clean version with a null
			// effective time) cannot anchor the window -> fail closed.
			return "", false, none
		}

		// RETENTION CORROBORATION (per leg). When the clean run reaches the OLDEST
		// retained version WITHOUT observing a break, we cannot, from history alone,
		// rule out that older WEAKENED versions aged out of retention. Require positive
		// proof that the oldest retained version is the ruleset's CREATION: its
		// effective time must be at-or-before the ruleset's CreatedAt (the creation
		// version is still retained). Otherwise older versions were pruned and the
		// window cannot be corroborated -> RetentionCapped, fail closed.
		if !brokeObserved {
			created, haveCreated := createdAt[id]
			if !haveCreated || created.IsZero() || legStart.After(created) {
				ev.RetentionCapped = true
				return "", false, ev
			}
		}
		// version-id gap check: a hole in the monotonic version_id sequence WITHIN the
		// clean run means an intermediate version was pruned and we cannot prove it was
		// clean -> fail closed (defense-in-depth against mid-history retention).
		if hasVersionIDGap(run) {
			ev.RetentionCapped = true
			return "", false, ev
		}

		if legStart.After(latestStart) {
			latestStart = legStart
		}
	}

	if latestStart.IsZero() {
		return "", false, none // no clean start computed -> undetermined.
	}
	// round the window start to whole seconds so the recorded WindowStartAt and the
	// since= query that anchors R0 are reproducible (RFC3339 has no sub-second here).
	latestStart = latestStart.UTC().Truncate(time.Second)
	ev.WindowStartAt = formatContinuityTime(latestStart)
	ev.EarliestHistoryAt = formatContinuityTime(earliestRetained)

	// global retention guard (redundant with the per-leg creation check, kept as a
	// belt-and-braces): the earliest readable version must not be newer than the
	// window start.
	if earliestRetained.After(latestStart) {
		ev.RetentionCapped = true
		return "", false, ev
	}

	// map the start TIME to a start COMMIT on the protected branch: the OLDEST commit
	// at-or-after the window start. R0 is approximate (the start time is the ruleset
	// effective time, not a commit time).
	startRev, ok := startCommitAtOrAfter(ctx, svc, owner, repo, branch, latestStart, queriedSHA)
	if !ok || startRev == "" {
		return "", false, ev // commit-walk truncation/error -> fail closed.
	}

	ev.WeakenedAt = "" // explicit: clean window.
	return startRev, true, ev
}

const (
	continuityMethodNone    = "none"
	continuityMethodHistory = "ruleset-history"
)

// currentRulesetFacts returns, for the head rulesets: the set of bypass actors
// (the narrowness bound — a historical version is narrow only if its bypass actors
// are a SUBSET of this set), and each ruleset's CreatedAt (creation-corroboration
// for the retention check). complete is false if ANY ruleset is unreadable —
// without the authoritative current state we cannot bound narrowness or corroborate
// retention, so continuity fails closed.
func currentRulesetFacts(ctx context.Context, svc ReviewService, owner, repo string, idSet map[int64]struct{}) (map[string]struct{}, map[int64]time.Time, bool) {
	set := map[string]struct{}{}
	created := map[int64]time.Time{}
	for id := range idSet {
		rs, resp, err := svc.GetRuleset(ctx, owner, repo, id, true)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err != nil || rs == nil {
			return nil, nil, false // current state unknown -> cannot bound narrow.
		}
		for _, a := range rs.GetBypassActors() {
			if a == nil {
				continue
			}
			set[formatBypassActor(a)] = struct{}{}
		}
		created[id] = rs.GetCreatedAt().UTC()
	}
	return set, created, true
}

// repoDefaultBranch returns the repo's default branch, or "" when unreadable. A ""
// result makes a "~DEFAULT_BRANCH"-only ruleset version fail closed (we cannot
// prove it covered the artifact's protected branch).
func repoDefaultBranch(ctx context.Context, svc ReviewService, owner, repo string) string {
	r, resp, err := svc.GetRepository(ctx, owner, repo)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err != nil || r == nil {
		return ""
	}
	return r.GetDefaultBranch()
}

// hasVersionIDGap reports whether the clean run (newest->oldest) has a hole in its
// monotonic version_id sequence — i.e. some adjacent pair differs by more than 1,
// which means an intermediate version was pruned/aged out and cannot be proven
// clean. A zero/unknown version id (<=0) is treated as a gap (fail closed). The run
// is sorted by version_id descending here so it does not depend on the timestamp
// ordering.
func hasVersionIDGap(run []historyVersion) bool {
	if len(run) <= 1 {
		// a single-version run has no intermediate gap, but a zero id is unprovable.
		return len(run) == 1 && run[0].versionID <= 0
	}
	ids := make([]int64, len(run))
	for i, v := range run {
		if v.versionID <= 0 {
			return true // an unknown version id cannot be proven contiguous.
		}
		ids[i] = v.versionID
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] > ids[j] }) // descending
	for i := 1; i < len(ids); i++ {
		if ids[i-1]-ids[i] != 1 {
			return true // a hole in the sequence -> a version was pruned.
		}
	}
	return false
}

// historyVersion is the per-version state plus its effective time and version id,
// in the order returned by the API (newest first).
type historyVersion struct {
	versionID int64
	updatedAt time.Time
	state     *RulesetVersionState
}

// walkRulesetHistory fetches a ruleset's full version history (paginated) and the
// STATE of each version, newest->oldest. ok is false (fail closed) on any 403/404/
// unreadable history, an unreadable version state, or pagination/version-cap
// truncation; HistoryComplete on ev is set false in those cases.
func walkRulesetHistory(ctx context.Context, svc ReviewService, owner, repo string, id int64, ev *SourceReviewContinuityEvidence) ([]historyVersion, bool) {
	opts := &gh.ListOptions{PerPage: 100}
	var metas []*RulesetVersion
	for attempt := 0; attempt < continuityMaxHistoryPages; attempt++ {
		page, resp, err := svc.GetRulesetHistory(ctx, owner, repo, id, opts)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err != nil {
			ev.HistoryComplete = false
			return nil, false // 403/404/unreadable -> fail closed (never "no changes").
		}
		metas = append(metas, page...)
		if len(metas) > continuityMaxVersions {
			ev.HistoryComplete = false
			return nil, false
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
		if attempt == continuityMaxHistoryPages-1 {
			ev.HistoryComplete = false
			return nil, false // more pages remain but we hit the cap.
		}
	}
	if len(metas) == 0 {
		ev.HistoryComplete = false
		return nil, false
	}

	out := make([]historyVersion, 0, len(metas))
	for _, m := range metas {
		if m == nil {
			ev.HistoryComplete = false
			return nil, false
		}
		state, resp, err := svc.GetRulesetVersion(ctx, owner, repo, id, m.VersionID)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err != nil || state == nil {
			ev.HistoryComplete = false
			return nil, false // unreadable version state -> fail closed.
		}
		ev.VersionsWalked++
		out = append(out, historyVersion{versionID: m.VersionID, updatedAt: m.UpdatedAt, state: state})
	}

	// guarantee a deterministic newest->oldest order independent of server order:
	// primary key UpdatedAt descending, tie-broken by VersionID descending so that
	// same-instant versions sort deterministically (reproducible signed evidence)
	// and the contiguous-run boundary is stable.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].updatedAt.Equal(out[j].updatedAt) {
			return out[i].versionID > out[j].versionID
		}
		return out[i].updatedAt.After(out[j].updatedAt)
	})
	return out, true
}

// legCleanStart finds the longest CONTIGUOUS clean run from the current (newest)
// version backward. It returns: the run's earliest version's effective time
// (start); the time of the version that broke the run (weakenedAt, when !clean);
// brokeObserved — whether a break was actually seen (vs the run reaching the oldest
// retained version); the clean-run slice (for the version-id gap check); and clean.
//
// Because continuity must hold from the attested revision back to the start, the
// run MUST begin at the newest version: if the newest version is not clean,
// continuity is broken NOW and the whole leg fails. When the run reaches the oldest
// retained version WITHOUT a break (brokeObserved=false), the caller must separately
// corroborate the oldest retained version is the ruleset creation (retention cap).
func legCleanStart(versions []historyVersion, branch, defaultBranch string, currentBypass map[string]struct{}) (start, weakenedAt time.Time, brokeObserved bool, run []historyVersion, clean bool) {
	for i, v := range versions { // newest -> oldest
		if !versionEnforcesL3(v.state, branch, defaultBranch, currentBypass) {
			if i == 0 {
				return time.Time{}, v.updatedAt, true, nil, false // broken at the head -> no window.
			}
			// a break older than the head ends the clean run; start was the previous
			// (newer) version's time, already recorded in `start`.
			return start, time.Time{}, true, run, true
		}
		start = v.updatedAt // extend the clean run to this (older) version.
		run = append(run, v)
	}
	return start, time.Time{}, false, run, true // every retained version clean (no break seen).
}

// versionEnforcesL3 reports whether a single historical ruleset version enforces
// the L3-relevant controls. DEFENSIVE: an unknown/missing enforcement is treated
// as NON-active; a missing rule is NOT present; a missing/non-targeting ref_name
// fails; a bypass actor outside the current narrow set fails. Never
// default-to-satisfied.
func versionEnforcesL3(state *RulesetVersionState, branch, defaultBranch string, currentBypass map[string]struct{}) bool {
	if state == nil {
		return false
	}
	// enforcement must be exactly "active" (evaluate/disabled/unknown -> not enforced).
	if state.Enforcement != string(gh.RulesetEnforcementActive) {
		return false
	}
	if !refTargetsBranch(state.Conditions, branch, defaultBranch) {
		return false
	}
	r := state.Rules
	if r == nil {
		return false // no rules object -> nothing present.
	}
	// required L3 rule types: force-push blocked (NonFastForward), >=1 required
	// status check, retained/linear-or-deletion history.
	if r.NonFastForward == nil {
		return false
	}
	if r.RequiredStatusChecks == nil || len(r.RequiredStatusChecks.RequiredStatusChecks) == 0 {
		return false
	}
	if r.RequiredLinearHistory == nil && r.Deletion == nil {
		return false
	}
	// bypass narrowness: every actor in this version must be in the current set.
	for _, a := range state.BypassActors {
		if a == nil {
			continue
		}
		if _, ok := currentBypass[formatBypassActor(a)]; !ok {
			return false // a bypass wider than current -> weakened.
		}
	}
	return true
}

// refTargetsBranch reports whether a version's conditions target the branch and do
// NOT exclude it. A nil conditions/ref_name is ambiguous -> not targeting (fail
// closed). FAIL-CLOSED on the exclude side: any exclude pattern that matches OR
// could plausibly match the branch (a glob) is treated as an exclusion. The include
// side is STRICT: only a pattern we can prove targets the branch counts.
func refTargetsBranch(cond *gh.RepositoryRulesetConditions, branch, defaultBranch string) bool {
	if cond == nil || cond.RefName == nil {
		return false
	}
	ref := cond.RefName
	if refExcludesBranch(ref.Exclude, branch, defaultBranch) {
		return false // explicitly (or possibly) excluded -> not protected in this window.
	}
	return refIncludesBranch(ref.Include, branch, defaultBranch)
}

// refIncludesBranch reports whether any include pattern PROVABLY targets branch:
// "~ALL"; "~DEFAULT_BRANCH" only when branch is the repo default; the exact bare
// branch; or the exact "refs/heads/<branch>". A glob/unrecognized include does NOT
// count (fail closed — we will not claim a window we cannot prove covered branch).
func refIncludesBranch(patterns []string, branch, defaultBranch string) bool {
	full := "refs/heads/" + branch
	for _, p := range patterns {
		switch p {
		case "~ALL":
			return true
		case "~DEFAULT_BRANCH":
			if defaultBranch != "" && branch == defaultBranch {
				return true
			}
		case branch, full:
			return true
		}
	}
	return false
}

// refExcludesBranch reports whether any exclude pattern matches OR could match
// branch. Besides the exact/literal forms it treats ANY pattern containing a glob
// metacharacter (* ? [ ]) as a POSSIBLE match (fail closed): we cannot cheaply and
// safely evaluate GitHub's fnmatch here, and an exclude that carves the branch out
// must never read as "still protected". "~DEFAULT_BRANCH" excludes only when branch
// is the default; an unknown default branch is treated as a possible exclusion.
func refExcludesBranch(patterns []string, branch, defaultBranch string) bool {
	full := "refs/heads/" + branch
	for _, p := range patterns {
		switch {
		case p == "~ALL":
			return true
		case p == "~DEFAULT_BRANCH":
			if defaultBranch == "" || branch == defaultBranch {
				return true // default unknown -> can't rule it out; or branch IS default.
			}
		case p == branch, p == full:
			return true
		case strings.ContainsAny(p, "*?[]"):
			return true // a glob exclude could match branch -> fail closed.
		}
	}
	return false
}

// continuityMaxCommitPages caps the commit pages walked when resolving the start
// time to a commit. Hitting it means the at-or-after-start commit set could not be
// fully enumerated -> fail closed (we will not anchor R0 on a truncated list).
const continuityMaxCommitPages = 30

// startCommitAtOrAfter maps the continuity start TIME to a start COMMIT R0: the
// commit on the protected branch with the EARLIEST committer date that is still
// at-or-after the start time. It lists branch commits with since=start (committer-
// date inclusive). Rather than assume strict newest-first ordering (rebases /
// cherry-picks make committer date non-monotonic vs graph order), it explicitly
// picks the minimum committer-date commit whose date is >= start. R0 is documented
// as APPROXIMATE. Fails closed (ok=false) on any read error, pagination cap (a
// truncated list could omit the true earliest commit), no commit at-or-after start,
// or a chosen commit whose committer date is unexpectedly before start.
func startCommitAtOrAfter(ctx context.Context, svc ReviewService, owner, repo, branch string, start time.Time, _ string) (string, bool) {
	if branch == "" || start.IsZero() {
		return "", false
	}
	start = start.UTC()
	opts := &gh.CommitsListOptions{
		SHA:         branch,
		Since:       start,
		ListOptions: gh.ListOptions{PerPage: 100},
	}
	var bestSHA string
	var bestWhen time.Time
	for attempt := 0; attempt < continuityMaxCommitPages; attempt++ {
		commits, resp, err := svc.ListCommits(ctx, owner, repo, opts)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err != nil {
			return "", false // read error -> cannot anchor R0 -> fail closed.
		}
		for _, c := range commits {
			if c == nil || c.GetSHA() == "" || c.GetCommit() == nil || c.GetCommit().GetCommitter() == nil {
				continue // no committer date -> cannot place it on the timeline.
			}
			when := c.GetCommit().GetCommitter().GetDate().UTC()
			if when.Before(start) {
				continue // outside the window (defensive; since= should exclude these).
			}
			if bestSHA == "" || when.Before(bestWhen) {
				bestSHA = c.GetSHA()
				bestWhen = when
			}
		}
		if resp == nil || resp.NextPage == 0 {
			if bestSHA == "" {
				return "", false // no commit at-or-after start -> cannot anchor R0.
			}
			return truncateRunes(bestSHA, srMaxSHALen), true
		}
		opts.Page = resp.NextPage
		if attempt == continuityMaxCommitPages-1 {
			return "", false // more pages remain but we hit the cap -> fail closed.
		}
	}
	return "", false
}

// formatContinuityTime renders a continuity timestamp as bounded UTC RFC3339, or
// "" for the zero time.
func formatContinuityTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return truncateRunes(t.UTC().Format(time.RFC3339), srMaxTimestampLen)
}

// formatBypassActor renders a ruleset bypass actor as
// "<ActorType>:<ActorID>:<BypassMode>". ActorType and BypassMode are
// pointer-to-named-string enums with no String() method, so they are nil-guarded
// and converted directly; an absent segment serializes empty rather than panics.
func formatBypassActor(a *gh.BypassActor) string {
	actorType := ""
	if a.ActorType != nil {
		actorType = string(*a.ActorType)
	}
	bypassMode := ""
	if a.BypassMode != nil {
		bypassMode = string(*a.BypassMode)
	}
	return truncateRunes(fmt.Sprintf("%s:%d:%s", actorType, a.GetActorID(), bypassMode), srMaxStringLen)
}

// listReviews paginates ListReviews for a pull request.
func listReviews(ctx context.Context, svc ReviewService, owner, repo string, number int) ([]*gh.PullRequestReview, error) {
	const maxPages = 20
	opts := &gh.ListOptions{PerPage: 100}
	var all []*gh.PullRequestReview
	for attempt := 0; attempt < maxPages; attempt++ {
		revs, resp, err := svc.ListReviews(ctx, owner, repo, number, opts)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err != nil {
			return nil, fmt.Errorf("failed to list reviews for PR #%d: %w", number, err)
		}
		all = append(all, revs...)
		if resp == nil || resp.NextPage == 0 {
			break
		}
		if attempt == maxPages-1 {
			return nil, fmt.Errorf("review pagination exceeded %d pages for PR #%d", maxPages, number)
		}
		opts.Page = resp.NextPage
	}
	return all, nil
}

// latestOpinionatedPerUser reduces reviews to the latest opinionated review
// (APPROVED, CHANGES_REQUESTED, or DISMISSED) per user.id. Grouping by id (not
// login) and taking the latest by submitted-at resolves a
// COMMENT->APPROVE->CHANGES_REQUESTED sequence to its final state.
func latestOpinionatedPerUser(reviews []*gh.PullRequestReview) map[int64]*gh.PullRequestReview {
	latest := map[int64]*gh.PullRequestReview{}
	for _, r := range reviews {
		if r == nil || r.GetUser() == nil {
			continue
		}
		if !isOpinionated(strings.ToUpper(r.GetState())) {
			continue
		}
		uid := r.GetUser().GetID()
		if cur, ok := latest[uid]; !ok || reviewLater(r, cur) {
			latest[uid] = r
		}
	}
	return latest
}

// isOpinionated reports whether a review state carries a verdict.
func isOpinionated(state string) bool {
	switch state {
	case reviewStateApproved, reviewStateChangesRequested, reviewStateDismissed:
		return true
	default:
		return false
	}
}

// reviewLater reports whether a is more recent than b (submitted-at, then id).
func reviewLater(a, b *gh.PullRequestReview) bool {
	at, bt := a.GetSubmittedAt().Time, b.GetSubmittedAt().Time
	if at.Equal(bt) {
		return a.GetID() > b.GetID()
	}
	return at.After(bt)
}

// sortApprovers orders approvers deterministically (login, submittedAt, commitId).
func sortApprovers(approvers []SourceReviewApprover) {
	sort.SliceStable(approvers, func(i, j int) bool {
		a, b := approvers[i], approvers[j]
		if a.Login != b.Login {
			return a.Login < b.Login
		}
		if a.SubmittedAt != b.SubmittedAt {
			return a.SubmittedAt < b.SubmittedAt
		}
		return a.CommitID < b.CommitID
	})
}

// formatTimestamp renders a GitHub timestamp as bounded UTC RFC3339, or "".
func formatTimestamp(ts gh.Timestamp) string {
	if ts.IsZero() {
		return ""
	}
	return truncateRunes(ts.UTC().Format(time.RFC3339), srMaxTimestampLen)
}

// normalizeRef strips a refs/heads/ prefix so the predicate ref is a branch name.
func normalizeRef(ref string) string {
	return strings.TrimPrefix(ref, "refs/heads/")
}

// normalizeAssociation constrains the untrusted author_association to the known
// GitHub enum (mirrors code-scan's normalizeLevel). An unrecognized or absent
// value yields "" so the field is omitted rather than failing schema validation
// if GitHub ever returns a new value. Evidence only — never gated.
func normalizeAssociation(s string) string {
	switch strings.ToUpper(s) {
	case "OWNER", "MEMBER", "COLLABORATOR", "CONTRIBUTOR",
		"FIRST_TIMER", "FIRST_TIME_CONTRIBUTOR", "MANNEQUIN", "NONE":
		return strings.ToUpper(s)
	default:
		return ""
	}
}

// Generate produces the JSON representation of the source-review predicate.
func (c *SourceReview) Generate() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

// GenerateSourceReview generates and validates a source-review attestation
// predicate, fetching review evidence from the GitHub API.
func GenerateSourceReview(opts SourceReviewOptions, outputFile string) error {
	client, err := ghclient.NewClient()
	if err != nil {
		return fmt.Errorf("failed to create GitHub client: %w", err)
	}

	c, err := NewSourceReview(context.Background(), NewGitHubReviewService(client), opts)
	if err != nil {
		return err
	}

	output, err := c.Generate()
	if err != nil {
		return fmt.Errorf("failed to generate predicate: %w", err)
	}

	if err := ValidateSourceReview(output); err != nil {
		return fmt.Errorf("failed to validate source-review: %w", err)
	}

	return writeOutput(output, outputFile)
}
