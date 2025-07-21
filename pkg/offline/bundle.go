// Package offline provides functionality for offline attestation verification
// using pre-downloaded Sigstore bundles and trusted roots.
package offline

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// sigstore bundle containing verification material
type Bundle struct {
	MediaType            string               `json:"mediaType"`
	VerificationMaterial VerificationMaterial `json:"verificationMaterial"`
	MessageSignature     *MessageSignature    `json:"messageSignature,omitempty"`
	DsseEnvelope         *DsseEnvelope        `json:"dsseEnvelope,omitempty"`
}

// cryptographic material for verification
type VerificationMaterial struct {
	Certificate               *Certificate               `json:"x509CertificateChain,omitempty"`
	PublicKey                 *PublicKey                 `json:"publicKey,omitempty"`
	TimestampVerificationData *TimestampVerificationData `json:"timestampVerificationData,omitempty"`
	TlogEntries               []TlogEntry                `json:"tlogEntries,omitempty"`
}

// certificate chain
type Certificate struct {
	Certificates []CertificateBytes `json:"certificates"`
}

// certificate bytes
type CertificateBytes struct {
	RawBytes []byte `json:"rawBytes"`
}

// public key for verification
type PublicKey struct {
	RawBytes []byte          `json:"rawBytes"`
	KeyType  string          `json:"keyDetails"`
	ValidFor *ValidityPeriod `json:"validFor,omitempty"`
}

// ValidityPeriod represents the validity period of a key
type ValidityPeriod struct {
	Start *int64 `json:"start,omitempty"`
	End   *int64 `json:"end,omitempty"`
}

// timestamp verification information
type TimestampVerificationData struct {
	Rfc3161Timestamps []Rfc3161Timestamp `json:"rfc3161Timestamps,omitempty"`
}

// rfc3161Timestamp represents an RFC 3161 timestamp
type Rfc3161Timestamp struct {
	SignedTimestamp []byte `json:"signedTimestamp"`
}

// tlogEntry represents an entry in the transparency log
type TlogEntry struct {
	LogIndex          *int64            `json:"logIndex,omitempty"`
	LogId             *LogId            `json:"logId,omitempty"`
	KindVersion       *KindVersion      `json:"kindVersion,omitempty"`
	IntegratedTime    *int64            `json:"integratedTime,omitempty"`
	InclusionPromise  *InclusionPromise `json:"inclusionPromise,omitempty"`
	InclusionProof    *InclusionProof   `json:"inclusionProof,omitempty"`
	CanonicalizedBody []byte            `json:"canonicalizedBody,omitempty"`
}

// logId transparency log identifier
type LogId struct {
	KeyId []byte `json:"keyId"`
}

// kind and version of a log entry
type KindVersion struct {
	Kind    string `json:"kind"`
	Version string `json:"version"`
}

// inclusion promise from the transparency log
type InclusionPromise struct {
	SignedEntryTimestamp []byte `json:"signedEntryTimestamp"`
}

// inclusion proof from the transparency log
type InclusionProof struct {
	LogIndex   int64       `json:"logIndex"`
	RootHash   []byte      `json:"rootHash"`
	TreeSize   int64       `json:"treeSize"`
	Hashes     [][]byte    `json:"hashes"`
	Checkpoint *Checkpoint `json:"checkpoint,omitempty"`
}

// checkpoint from the transparency log
type Checkpoint struct {
	Envelope string `json:"envelope"`
}

// message signature
type MessageSignature struct {
	MessageDigest *HashOutput `json:"messageDigest"`
	Signature     []byte      `json:"signature"`
}

// DSSE (Dead Simple Signing Envelope)
type DsseEnvelope struct {
	Payload     []byte          `json:"payload"`
	PayloadType string          `json:"payloadType"`
	Signatures  []DsseSignature `json:"signatures"`
}

// signature within a DSSE envelope
type DsseSignature struct {
	Signature []byte `json:"sig"`
	Keyid     string `json:"keyid,omitempty"`
}

// hash digest
type HashOutput struct {
	Algorithm string `json:"algorithm"`
	Digest    []byte `json:"digest"`
}

// subject of an attestation
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// loads Sigstore bundles from a file (JSON or JSONL format)
func LoadBundles(filepath string) ([]Bundle, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open bundle file %s: %w", filepath, err)
	}
	defer func() { _ = file.Close() }()

	return ParseBundles(file)
}

// parses bundles from an io.Reader, supporting both JSON and JSONL formats
func ParseBundles(reader io.Reader) ([]Bundle, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read bundle data: %w", err)
	}

	var bundles []Bundle

	// parse as single JSON object first
	var singleBundle Bundle
	if err := json.Unmarshal(data, &singleBundle); err == nil {
		bundles = append(bundles, singleBundle)
		return bundles, nil
	}

	// parse as JSONL (newline-delimited JSON)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if line == "" {
			continue // skip empty lines
		}

		var bundle Bundle
		if err := json.Unmarshal([]byte(line), &bundle); err != nil {
			return nil, fmt.Errorf("failed to parse bundle on line %d: %w", lineNum, err)
		}

		bundles = append(bundles, bundle)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan bundle file: %w", err)
	}

	if len(bundles) == 0 {
		return nil, fmt.Errorf("no valid bundles found in file")
	}

	return bundles, nil
}

// writes bundles to a file in JSONL format
func WriteBundles(filepath string, bundles []Bundle) error {
	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create bundle file %s: %w", filepath, err)
	}
	defer func() { _ = file.Close() }()

	encoder := json.NewEncoder(file)
	for _, bundle := range bundles {
		if err := encoder.Encode(bundle); err != nil {
			return fmt.Errorf("failed to write bundle: %w", err)
		}
	}

	return nil
}

// extracts the subject (artifact) information from a bundle
func GetSubjectFromBundle(bundle Bundle) (*Subject, error) {
	if bundle.DsseEnvelope == nil {
		return nil, fmt.Errorf("bundle does not contain DSSE envelope")
	}

	// Parse the DSSE payload to extract subject information
	var envelope struct {
		Predicate struct {
			Subject []Subject `json:"subject"`
		} `json:"predicate"`
	}

	if err := json.Unmarshal(bundle.DsseEnvelope.Payload, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse DSSE payload: %w", err)
	}

	if len(envelope.Predicate.Subject) == 0 {
		return nil, fmt.Errorf("no subjects found in attestation")
	}

	return &envelope.Predicate.Subject[0], nil
}

// calculates the SHA256 digest of a file
func CalculateDigest(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", fmt.Errorf("failed to open file %s: %w", filepath, err)
	}
	defer func() { _ = file.Close() }()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("failed to calculate digest: %w", err)
	}

	return fmt.Sprintf("sha256:%x", hash.Sum(nil)), nil
}

// performs basic validation on a bundle
func ValidateBundle(bundle Bundle) error {
	if bundle.MediaType == "" {
		return fmt.Errorf("bundle missing mediaType")
	}

	if bundle.VerificationMaterial.Certificate == nil && bundle.VerificationMaterial.PublicKey == nil {
		return fmt.Errorf("bundle missing both certificate and public key")
	}

	if bundle.MessageSignature == nil && bundle.DsseEnvelope == nil {
		return fmt.Errorf("bundle missing both message signature and DSSE envelope")
	}

	return nil
}
