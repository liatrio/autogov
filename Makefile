.PHONY: build test clean lint format all install verify help

BINARY_NAME := autogov-verify
BINARY_DIR := bin
VERSION ?= $(shell git describe --tags --always --dirty)
LDFLAGS := -X main.version=$(VERSION)

# note: for organization-level verification, you'll need to set up a Personal Access Token
# with appropriate organization permissions in your GitHub organization's settings

all: verify build

build:
	@echo "Building $(BINARY_NAME) version $(VERSION)"
	@mkdir -p $(BINARY_DIR)
	@go build -ldflags "$(LDFLAGS)" -o $(BINARY_DIR)/$(BINARY_NAME) .

test:
	@echo "Running tests..."
	@go test -v -race -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out

lint:
	@echo "Running linter..."
	@golangci-lint run

format:
	@echo "Formatting code..."
	@gofmt -w .

clean:
	@echo "Cleaning up..."
	@rm -rf $(BINARY_DIR) coverage.out

install: build
	@echo "Installing $(BINARY_NAME) to /usr/local/bin"
	@sudo cp $(BINARY_DIR)/$(BINARY_NAME) /usr/local/bin/

verify: format lint test

help:
	@echo "Available targets:"
	@echo "  all       - Run verify and build (default)"
	@echo "  build     - Build the binary"
	@echo "  test      - Run tests with coverage"
	@echo "  lint      - Run linter"
	@echo "  format    - Format code"
	@echo "  clean     - Clean build artifacts"
	@echo "  install   - Install binary to /usr/local/bin"
	@echo "  verify    - Run format, lint, and test"
	@echo "  help      - Show this help message"
