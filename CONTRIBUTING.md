# Contributing to AutoGov

Thank you for your interest in contributing to AutoGov! This document provides guidelines for contributing to the project.

## Getting Started

### Prerequisites

- Go 1.25 or higher
- GitHub CLI (`gh`) for trusted root fetching
- Docker for container registry access
- golangci-lint for code quality checks
- [Task](https://taskfile.dev) for build automation
- GitHub Personal Access Token with appropriate permissions

### Local Development Setup

```bash
# Clone and setup
git clone https://github.com/liatrio/autogov-verify
cd autogov-verify

# Install dependencies
go mod download

# Run tests
task test

# Build binary
task build

# Run linter
task lint
```

### Available Task Commands

```bash
task --list       # Show all available tasks
task              # Run verify and build (default)
task build        # Build the binary
task test         # Run tests with coverage
task lint         # Run linter
task format       # Format code
task verify       # Run format, lint, and test
task install      # Install binary to /usr/local/bin
task clean        # Clean build artifacts
```

## Contributing Process

1. **Create an issue** for new features or bugs
   - Clearly describe the problem or enhancement
   - Include steps to reproduce for bugs
   - Provide context and use cases for features

2. **Fork the repository** and create a feature branch
   - Use descriptive branch names (e.g., `feature/vsa-validation`, `fix/cert-parsing`)
   - Keep branches focused on a single change

3. **Write tests** for your changes
   - Maintain >75% test coverage
   - Include unit tests for all new functionality
   - Add integration tests for end-to-end workflows
   - Test error conditions and edge cases

4. **Run `task verify`** to ensure code quality
   - All tests must pass
   - Zero linter warnings required
   - Code must be properly formatted

5. **Submit a pull request** with a clear description
   - Reference related issues
   - Explain the changes and why they're needed
   - Include any breaking changes or migration notes

## Code Standards

### Go Best Practices

- Follow Go best practices and idioms
- Prefer functional programming patterns over object-oriented approaches
- Use meaningful variable and function names
- Keep functions small and focused on a single responsibility
- Use early returns to reduce nesting

### Error Handling

- Add comprehensive error handling with context
- Use `fmt.Errorf` with `%w` verb to wrap errors
- Provide meaningful error messages that help users understand the issue
- Use structured error types where appropriate (see `pkg/vsa/validation.go`)

### Documentation

- Document all public APIs with GoDoc comments
- Include examples in documentation where helpful
- Keep comments focused on "why" not "what"
- Update README.md for user-facing changes

### Testing

- Write table-driven tests where appropriate
- Use meaningful test names that describe the scenario
- Test both success and failure cases
- Use constants for test data to avoid duplication
- Add integration tests for complex workflows

### Code Quality

- Ensure zero linter warnings (`golangci-lint run`)
- Use `gofmt` for consistent formatting
- Keep cyclomatic complexity low
- Avoid deep nesting and long functions
- Use interfaces to improve testability

## Architecture Guidelines

The project follows a modular architecture. See the [Architecture Overview](README.md#architecture-overview) in the README for a full list of packages and their responsibilities.

### Design Principles

- **Single Responsibility**: Each package and function should have one clear purpose
- **Dependency Injection**: Use interfaces and dependency injection for testability
- **Error Transparency**: Errors should bubble up with sufficient context
- **Configuration**: Support both CLI flags and environment variables
- **Extensibility**: Design for future enhancements without breaking changes

## Testing Guidelines

### Unit Tests

```bash
# Run unit tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific package tests
go test ./pkg/vsa/
```

### Integration Tests

```bash
# Integration tests with real attestations
export GITHUB_AUTH_TOKEN=your_token
go test -tags=integration ./...
```

### Benchmark Tests

```bash
# Run benchmark tests
go test -bench=. ./...
```

### Test Coverage Requirements

- Minimum 75% test coverage for all packages
- 90%+ coverage for critical paths (verification, VSA generation)
- All public APIs must have comprehensive tests
- Error conditions must be tested

## Security Considerations

- Never hardcode credentials or tokens
- Validate all inputs, especially from external sources
- Use secure defaults for cryptographic operations
- Follow principle of least privilege for permissions
- Be mindful of potential injection attacks in policy evaluation

## Performance Guidelines

- Profile code changes that may affect performance
- Use efficient algorithms and data structures
- Avoid unnecessary allocations in hot paths
- Consider caching for expensive operations
- Document any performance implications

## Documentation Updates

When contributing, ensure you update relevant documentation:

- **README.md**: User-facing features, CLI changes, examples
- **GoDoc comments**: All public APIs
- **Architecture docs**: Significant design changes
- **Examples**: Update examples for new features

## Release Process

Contributors don't need to manage releases, but understanding the process helps:

1. Changes are merged to `main` branch
2. Maintainers create release tags following semantic versioning
3. GitHub Actions automatically builds and publishes releases
4. Release notes are generated from pull request descriptions

## Getting Help

- **Issues**: For bugs, feature requests, and questions
- **Discussions**: For general questions about usage or architecture
- **Code Reviews**: Maintainers will provide feedback on pull requests

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you are expected to uphold this code.

Thank you for contributing to AutoGov!
