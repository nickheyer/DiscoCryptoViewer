.PHONY: build build-wasm build-webview build-ext proto proto-clean gen deps clean help pub pack

WEBVIEW_DIR := webview
BUF_IMAGE := bufbuild/buf:latest
BUF_RUN := docker run --rm \
	--volume "$(shell pwd):/workspace" \
	--workdir /workspace \
	--user "$(shell id -u):$(shell id -g)" \
	--env HOME=/tmp \
	$(BUF_IMAGE)

pub:
	vsce publish

pack:
	vsce package

# Full build: proto -> wasm -> webview -> extension
build: gen build-wasm build-webview build-ext

# Build the Go WASM engine
build-wasm:
	@echo "Building WASM engine..."
	bash wasm/build.sh

# Build the Svelte webview
build-webview:
	@echo "Building webview..."
	cd $(WEBVIEW_DIR) && npm run build

# Build the VS Code extension
build-ext:
	@echo "Building extension..."
	npm run compile

# Generate TypeScript types from proto files
proto:
	@echo "Generating protocol buffer code (using Docker)..."
	$(BUF_RUN) generate
	@echo "Proto generation complete!"

proto-clean:
	@echo "Cleaning generated proto files..."
	rm -rf pkg/proto
	rm -rf src/proto
	rm -rf $(WEBVIEW_DIR)/src/lib/proto
	@echo "Proto files cleaned!"

gen: proto-clean proto

# Install all dependencies
deps:
	@echo "Installing extension dependencies..."
	npm install
	@echo "Installing webview dependencies..."
	cd $(WEBVIEW_DIR) && npm install

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf dist
	@echo "Clean complete!"

help:
	@echo "Available commands:"
	@echo "  make build          - Full build (proto + wasm + webview + extension)"
	@echo "  make build-wasm     - Build Go WASM engine"
	@echo "  make build-webview  - Build Svelte webview"
	@echo "  make build-ext      - Build VS Code extension"
	@echo "  make gen            - Clean and regenerate proto TypeScript types"
	@echo "  make proto          - Generate TypeScript code from proto files"
	@echo "  make proto-clean    - Remove all generated proto files"
	@echo "  make deps           - Install all dependencies"
	@echo "  make clean          - Remove build artifacts"
	@echo "  make help           - Show this help message"
