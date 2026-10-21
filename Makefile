SHELL := /bin/bash

BINARY_NAME := sentinel
BIN_DIR     := bin
CMD_DIR     := ./cmd/sentinel

GOLANGCI_LINT_VERSION := latest
GOSEC_VERSION         := latest
GOVULNCHECK_VERSION   := latest

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help message
	@echo "Available targets:" && echo && \
	awk 'BEGIN {FS = ":.*?## "}; /^[a-zA-Z0-9_\-]+:.*?## / {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST) | sort

.PHONY: build
build: ## Build the binary into bin/sentinel
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BIN_DIR)/$(BINARY_NAME) $(CMD_DIR)

.PHONY: run
run: ## Run the sentinel locally (use ARGS="--config=..." to pass flags)
	go run $(CMD_DIR) $(ARGS)

.PHONY: test
test: ## Run all tests
	go test ./...

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: tidy
tidy: ## Tidy go modules
	go mod tidy

GOPATH_BIN := $(shell go env GOPATH)/bin
tool = $$(command -v $(1) 2>/dev/null || echo $(GOPATH_BIN)/$(1))

MODULE_GO_VERSION := $(shell go list -m -f '{{.GoVersion}}')
TOOL_GOTOOLCHAIN  := GOTOOLCHAIN=go$(MODULE_GO_VERSION)$(if $(word 3,$(subst ., ,$(MODULE_GO_VERSION))),,.0)

.PHONY: lint
lint: ## Run golangci-lint
	@command -v golangci-lint >/dev/null 2>&1 || \
		$(TOOL_GOTOOLCHAIN) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	$(call tool,golangci-lint) run ./...

.PHONY: gosec
gosec: ## Run gosec
	@command -v gosec >/dev/null 2>&1 || \
		$(TOOL_GOTOOLCHAIN) go install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)
	$(call tool,gosec) ./...

.PHONY: govulncheck
govulncheck: ## Run govulncheck
	@command -v govulncheck >/dev/null 2>&1 || \
		$(TOOL_GOTOOLCHAIN) go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	$(call tool,govulncheck) ./...

.PHONY: security
security: gosec govulncheck ## Run all security checks

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BIN_DIR)
