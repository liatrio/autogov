package source

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// SourceReviewControls is the enforced branch-protection evidence extracted from
// a signature-verified source-review attestation. It is the verifier-side view
// of the producer's technicalControls block (pkg/predicate.SourceReviewTechnicalControls);
// kept as a local mirror so pkg/source stays dependency-free (matching the
// SourceProvenancePredicate pattern).
type SourceReviewControls struct {
	ForcePushBlocked        bool
	RequiredLinearHistory   bool
	DeletionBlocked         bool
	RequiredSignatures      bool
	RequiredStatusChecks    []string
	BypassActors            []string
	BypassActorsComplete    bool
	ContinuityStartRevision string
	// TwoPartyReviewed is derived from the source-review summary (>= 2 distinct
	// approvers). It feeds the ORG_SOURCE_TWO_PARTY_REVIEWED annotation only —
	// review is the v1.2 "L4" tier, never folded into the numeric L3.
	TwoPartyReviewed bool
}

// sourceReviewPredicate parses only the source-review fields the L3 determination
// needs. Unknown fields are ignored.
type sourceReviewPredicate struct {
	Summary struct {
		DistinctApprovers int `json:"distinctApprovers"`
	} `json:"summary"`
	TechnicalControls *struct {
		ForcePushBlocked      bool     `json:"forcePushBlocked"`
		RequiredLinearHistory bool     `json:"requiredLinearHistory"`
		DeletionBlocked       bool     `json:"deletionBlocked"`
		RequiredSignatures    bool     `json:"requiredSignatures"`
		RequiredStatusChecks  []string `json:"requiredStatusChecks"`
		BypassActors          []string `json:"bypassActors"`
		BypassActorsComplete  bool     `json:"bypassActorsComplete"`
	} `json:"technicalControls"`
	ContinuityStartRevision string `json:"continuityStartRevision"`
}

// VerifySourceReviewControls loads a source-review attestation bundle, verifies
// its signature under an ENFORCED signer identity, and extracts the recorded
// technical controls. It mirrors VerifySourceProvenance's load→root→verify
// shape. It REQUIRES opts.CertIdentity: an unverified (WithoutIdentitiesUnsafe)
// source-review bundle must never be able to promote the source level, so the
// caller can only obtain controls from a verified signer. Any error means "no
// verified controls" — the caller degrades to the base level, it does not block.
func VerifySourceReviewControls(bundlePath string, opts VerifyOptions) (*SourceReviewControls, error) {
	if opts.CertIdentity == "" {
		return nil, fmt.Errorf("source-review controls require --cert-identity (refusing to promote the source level from an unverified signer)")
	}

	b, err := bundle.LoadJSONFromPath(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("load source-review bundle: %w", err)
	}

	trustedRoot, err := selectTrustedRootForBundle(b)
	if err != nil {
		return nil, fmt.Errorf("load trusted root: %w", err)
	}

	verifierOpts := []verify.VerifierOption{verify.WithObserverTimestamps(1)}
	if len(b.GetVerificationMaterial().GetTlogEntries()) > 0 {
		verifierOpts = append(verifierOpts, verify.WithTransparencyLog(1))
	}
	v, err := verify.NewVerifier(trustedRoot, verifierOpts...)
	if err != nil {
		return nil, fmt.Errorf("create verifier: %w", err)
	}

	certIssuer := opts.CertIssuer
	if certIssuer == "" {
		certIssuer = "https://token.actions.githubusercontent.com"
	}
	certID, err := verify.NewShortCertificateIdentity(certIssuer, "", opts.CertIdentity, "")
	if err != nil {
		return nil, fmt.Errorf("create identity policy: %w", err)
	}
	policy := verify.NewPolicy(verify.WithoutArtifactUnsafe(), verify.WithCertificateIdentity(certID))
	if _, err := v.Verify(b, policy); err != nil {
		return nil, fmt.Errorf("source-review signature verification failed: %w", err)
	}

	envelope := b.GetDsseEnvelope()
	if envelope == nil {
		return nil, fmt.Errorf("source-review bundle has no DSSE envelope")
	}
	var statement inTotoStatement
	if err := json.Unmarshal(envelope.GetPayload(), &statement); err != nil {
		return nil, fmt.Errorf("parse source-review statement: %w", err)
	}
	var pred sourceReviewPredicate
	if err := json.Unmarshal(statement.Predicate, &pred); err != nil {
		return nil, fmt.Errorf("parse source-review predicate: %w", err)
	}
	if pred.TechnicalControls == nil {
		return nil, fmt.Errorf("source-review predicate records no technicalControls")
	}

	tc := pred.TechnicalControls
	return &SourceReviewControls{
		ForcePushBlocked:        tc.ForcePushBlocked,
		RequiredLinearHistory:   tc.RequiredLinearHistory,
		DeletionBlocked:         tc.DeletionBlocked,
		RequiredSignatures:      tc.RequiredSignatures,
		RequiredStatusChecks:    tc.RequiredStatusChecks,
		BypassActors:            tc.BypassActors,
		BypassActorsComplete:    tc.BypassActorsComplete,
		ContinuityStartRevision: pred.ContinuityStartRevision,
		TwoPartyReviewed:        pred.Summary.DistinctApprovers >= 2,
	}, nil
}

// ComputeSourceLevelFromControls promotes the source level to SLSA_SOURCE_LEVEL_3
// when the enforced technical controls prove it, and emits the factual controls
// as non-numbered ORG_SOURCE_* annotations regardless of the numeric outcome.
//
// L3 is earned iff: force-push blocked AND at least one required status check AND
// retained/immutable history (linear-history OR deletion-blocked) AND the bypass
// list is AUTHORITATIVE (BypassActorsComplete) AND every bypass actor is narrow
// (allowlisted, or none at all) AND continuity is recorded. Two-party review is
// NOT required for L3 (it is the separate v1.2 review tier) and never produces a
// numeric SLSA_SOURCE_LEVEL_4 — only the ORG_SOURCE_TWO_PARTY_REVIEWED annotation.
//
// FAIL-CLOSED: BypassActorsComplete==false means an empty BypassActors is UNKNOWN
// (not "none"), so the bypass leg fails; an empty ContinuityStartRevision is
// UNDETERMINED, so the continuity leg fails. Either keeps the level at baseLevel.
func ComputeSourceLevelFromControls(tc *SourceReviewControls, allowedBypass []string, baseLevel string) (string, []string) {
	if tc == nil {
		return baseLevel, nil
	}

	var annotations []string
	if tc.ForcePushBlocked {
		annotations = append(annotations, "ORG_SOURCE_FORCE_PUSH_BLOCKED")
	}
	if tc.DeletionBlocked {
		annotations = append(annotations, "ORG_SOURCE_DELETION_BLOCKED")
	}
	if tc.RequiredLinearHistory {
		annotations = append(annotations, "ORG_SOURCE_LINEAR_HISTORY")
	}
	if tc.RequiredSignatures {
		annotations = append(annotations, "ORG_SOURCE_SIGNED_COMMITS")
	}
	if len(tc.RequiredStatusChecks) > 0 {
		annotations = append(annotations, "ORG_SOURCE_STATUS_CHECKS_REQUIRED")
	}
	if tc.TwoPartyReviewed {
		annotations = append(annotations, "ORG_SOURCE_TWO_PARTY_REVIEWED")
	}

	controlsMet := tc.ForcePushBlocked &&
		len(tc.RequiredStatusChecks) > 0 &&
		(tc.RequiredLinearHistory || tc.DeletionBlocked) &&
		tc.BypassActorsComplete &&
		bypassActorsAllNarrow(tc.BypassActors, allowedBypass)
	continuityMet := tc.ContinuityStartRevision != ""

	if controlsMet && continuityMet {
		return SLSASourceLevel3, annotations
	}
	return baseLevel, annotations
}

// bypassActorsAllNarrow reports whether every recorded bypass actor is narrow:
// an empty list (no bypass at all) is the cleanest pass; otherwise each actor's
// "<Type>:<ID>" (the formatted entry is "<Type>:<ID>:<Mode>") must be on the
// allowlist. An unrecognized actor type/id fails the leg (no L3).
func bypassActorsAllNarrow(actors, allowed []string) bool {
	if len(actors) == 0 {
		return true
	}
	allow := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		allow[a] = struct{}{}
	}
	for _, actor := range actors {
		typeID := actor
		if i := strings.LastIndex(actor, ":"); i >= 0 {
			typeID = actor[:i] // drop the ":<Mode>" suffix, match on Type:ID
		}
		if _, ok := allow[typeID]; !ok {
			return false
		}
	}
	return true
}
