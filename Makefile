# ------------------------------
# Project Configuration
# ------------------------------

# Set output binary directory and name for the webhook
BIN_DIR := bin
WEBHOOK_BINARY_FILE := federid-webhook
WEBHOOK_BINARY := $(BIN_DIR)/$(WEBHOOK_BINARY_FILE)

# Set release directory
RELEASE_DIR := release

# Define federid version
FEDERID_VERSION = 0.1.0

# ------------------------------
# Docker-related Variables
# ------------------------------

# Webhook Docker image settings
FEDERID_WEBHOOK_REGISTRY ?= federid
FEDERID_WEBHOOK_IMAGE_NAME := webhook
FEDERID_WEBHOOK_IMAGE_TAG ?= $(FEDERID_VERSION)
FEDERID_WEBHOOK_DOCKER_IMAGE := $(FEDERID_WEBHOOK_REGISTRY)/$(FEDERID_WEBHOOK_IMAGE_NAME):$(FEDERID_WEBHOOK_IMAGE_TAG)

# Tester Docker image settings
FEDERID_TESTER_REGISTRY ?= federid
FEDERID_TESTER_IMAGE_NAME := tester
FEDERID_TESTER_IMAGE_TAG ?= $(FEDERID_VERSION)
FEDERID_TESTER_DOCKER_IMAGE := $(FEDERID_TESTER_REGISTRY)/$(FEDERID_TESTER_IMAGE_NAME):$(FEDERID_TESTER_IMAGE_TAG)

# Spiffe helper Docker image settings
FEDERID_SPIFFE_HELPER_REGISTRY ?= federid
FEDERID_SPIFFE_HELPER_IMAGE_NAME := spiffe-helper
FEDERID_SPIFFE_HELPER_IMAGE_TAG ?= $(FEDERID_VERSION)
FEDERID_SPIFFE_HELPER_DOCKER_IMAGE := $(FEDERID_SPIFFE_HELPER_REGISTRY)/$(FEDERID_SPIFFE_HELPER_IMAGE_NAME):$(FEDERID_SPIFFE_HELPER_IMAGE_TAG)

# Go OS and architecture
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

# ------------------------------
# Default Target
# ------------------------------

# The default target: clean, build, and test
.PHONY: all
all: clean build test

# ------------------------------
# Build Targets
# ------------------------------

# Build target: compiles the Go application
.PHONY: build
build: $(WEBHOOK_BINARY)

# Target to build the Go application in cmd/webhook
$(WEBHOOK_BINARY):
	# Create binary directory if it doesn't exist
	mkdir -p $(BIN_DIR)
	# Build the webhook binary with the appropriate GOOS and GOARCH
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(WEBHOOK_BINARY) ./cmd/webhook
	@echo "Built $(WEBHOOK_BINARY)"

# ------------------------------
# Test Targets
# ------------------------------

# Placeholder test target
.PHONY: test
test:
	@echo "Running tests..."

# ------------------------------
# Clean Targets
# ------------------------------

# Clean target: removes the built webhook binary
.PHONY: clean
clean:
	@echo "Cleaning up..."
	rm $(WEBHOOK_BINARY) || true

# ------------------------------
# Docker Targets
# ------------------------------

# Build all Docker images: webhook, tester, and spiffe-helper
.PHONY: docker-build
docker-build: federid-docker-build helper-docker-build

# Push all Docker images: webhook, tester, and spiffe-helper
.PHONY: docker-push
docker-push: docker-build federid-docker-push helper-docker-push

# Docker build for federid webhook image
.PHONY: federid-docker-build
federid-docker-build: $(WEBHOOK_BINARY)
	@echo "Building federid Docker image $(FEDERID_WEBHOOK_DOCKER_IMAGE)"
	# Build the federid webhook Docker image from the Dockerfile in the current directory
	docker build -t $(FEDERID_WEBHOOK_DOCKER_IMAGE) -f Dockerfile .

# Docker push for federid webhook image
.PHONY: federid-docker-push
federid-docker-push: federid-docker-build
	@echo "Pushing federid Docker image $(FEDERID_WEBHOOK_DOCKER_IMAGE) to Docker Hub"
	# Push the federid webhook image to Docker Hub
	docker push $(FEDERID_WEBHOOK_DOCKER_IMAGE)

# Docker build for federid tester image
.PHONY: tester-docker-build
tester-docker-build:
	@echo "Building federid-tester Docker image $(FEDERID_TESTER_DOCKER_IMAGE)"
	# Navigate to the docker/federid-tester directory and build the tester Docker image
	cd docker/federid-tester && docker build -t $(FEDERID_TESTER_DOCKER_IMAGE) -f Dockerfile .

# Docker push for federid tester image
.PHONY: tester-docker-push
tester-docker-push: tester-docker-build
	@echo "Pushing federid-tester Docker image $(FEDERID_TESTER_DOCKER_IMAGE) to Docker Hub"
	# Push the federid tester image to Docker Hub
	docker push $(FEDERID_TESTER_DOCKER_IMAGE)

# Docker build for federid spiffe-helper image
.PHONY: helper-docker-build
helper-docker-build:
	@echo "Building federid-spiffe-helper Docker image $(FEDERID_SPIFFE_HELPER_DOCKER_IMAGE)"
	# Navigate to the docker/spiffe-helper directory and build the spiffe-helper Docker image
	cd docker/spiffe-helper && docker build -t $(FEDERID_SPIFFE_HELPER_DOCKER_IMAGE) -f Dockerfile .

# Docker push for federid spiffe-helper image
.PHONY: helper-docker-push
helper-docker-push: helper-docker-build
	@echo "Pushing federid-spiffe-helper Docker image $(FEDERID_SPIFFE_HELPER_DOCKER_IMAGE) to Docker Hub"
	# Push the federid spiffe-helper image to Docker Hub
	docker push $(FEDERID_SPIFFE_HELPER_DOCKER_IMAGE)

# ------------------------------
# Release Targets
# ------------------------------

# Release target: clean, build, docker push, helper build, and helm package
.PHONY: release
release: clean build federid-docker-push helper-docker-build helm-package
	# Create release directory and copy necessary files for release
	rm -rf $(RELEASE_DIR) && mkdir $(RELEASE_DIR)
	cp $(BIN_DIR)/$(WEBHOOK_BINARY_FILE) $(RELEASE_DIR)
	cp $(CHARTS_DIR)/federid*tgz $(RELEASE_DIR)/${HELM_CHART_FILE}
	@echo "Release created in $(RELEASE_DIR)"
