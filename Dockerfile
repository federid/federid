# Build the manager binary
FROM golang:1.23-bookworm AS builder

ARG LDFLAGS

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY cmd/webhook/main.go main.go
COPY pkg/ pkg/

# Build
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} GO111MODULE=on go build -a -o federid-webhook main.go

FROM debian:bookworm-slim

RUN DEBIAN_FRONTEND=noninteractive apt update && apt install -y procps

WORKDIR /
COPY --from=builder /workspace/federid-webhook .
# Kubernetes runAsNonRoot requires USER to be numeric
USER 65532:65532

ENTRYPOINT ["/federid-webhook"]
