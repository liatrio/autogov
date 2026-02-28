package predicate

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// writeOutput writes output to a file or stdout.
func writeOutput(output []byte, outputFile string) error {
	if outputFile != "" {
		if err := os.WriteFile(outputFile, output, 0600); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
	} else {
		fmt.Println(string(output))
	}
	return nil
}

// GenerateMetadata generates a metadata attestation predicate.
func GenerateMetadata(opts Options, outputFile string) error {
	m := NewFromOptions(opts)

	// validate input
	if opts.Type != ArtifactTypeContainerImage && opts.Type != ArtifactTypeBlob {
		return fmt.Errorf("invalid artifact type: %s", opts.Type)
	}

	if opts.Type == ArtifactTypeContainerImage {
		if opts.Registry == "" || opts.FullName == "" || opts.Digest == "" {
			return fmt.Errorf("container-image requires registry, fullName, and digest fields")
		}
	}

	if opts.Type == ArtifactTypeBlob && opts.SubjectPath == "" {
		return fmt.Errorf("blob requires subjectPath field")
	}

	output, err := m.Generate()
	if err != nil {
		return fmt.Errorf("failed to generate predicate: %w", err)
	}

	// validate against schema
	if err := ValidateMetadata(output); err != nil {
		return fmt.Errorf("failed to validate metadata: %w", err)
	}

	return writeOutput(output, outputFile)
}

// GenerateDepscan generates a dependency scan attestation predicate.
func GenerateDepscan(opts DependencyScanOptions, outputFile string) error {
	// read results
	data, err := os.ReadFile(opts.ResultsPath)
	if err != nil {
		return fmt.Errorf("failed to read results file: %w", err)
	}

	// parse results
	var results GrypeResult
	if err := json.Unmarshal(data, &results); err != nil {
		return fmt.Errorf("failed to parse results: %w", err)
	}

	// set timestamps
	opts.StartedAt = time.Now()
	opts.FinishedAt = time.Now()

	// create scan
	scan := NewDependencyScan(opts)

	// set scanner info
	scan.Scanner.Name = "grype"
	scan.Scanner.Version = results.Descriptor.Version
	scan.Scanner.URI = fmt.Sprintf("https://github.com/anchore/grype/releases/tag/v%s", results.Descriptor.Version)

	// set db info from Status (requires Grype v0.80+)
	if results.Descriptor.DB.Status != nil {
		scan.Scanner.DB.URI = results.Descriptor.DB.Status.From
		scan.Scanner.DB.Version = results.Descriptor.DB.Status.SchemaVersion
		scan.Scanner.DB.LastUpdate = results.Descriptor.DB.Status.Built
	}

	// convert results
	for _, match := range results.Matches {
		result := ScanResult{
			ID: match.Vulnerability.ID,
			Severity: []Severity{
				{
					Method: "nvd",
					Score:  match.Vulnerability.Severity,
				},
			},
		}

		// add cvss score if available
		if len(match.Vulnerability.CVSS) > 0 {
			result.Severity = append(result.Severity, Severity{
				Method: "cvss_score",
				Score:  fmt.Sprintf("%.1f", match.Vulnerability.CVSS[0].Metrics.BaseScore),
			})
		}

		scan.Scanner.Result = append(scan.Scanner.Result, result)
	}

	// generate output
	output, err := scan.Generate()
	if err != nil {
		return fmt.Errorf("failed to generate predicate: %w", err)
	}

	// validate against schema
	if err := ValidateDepscan(output); err != nil {
		return fmt.Errorf("failed to validate depscan: %w", err)
	}

	return writeOutput(output, outputFile)
}
