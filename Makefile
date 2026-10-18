VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all tidy build test vet lint install-tf clean

all: vet test build

tidy:
	go mod tidy

build:
	go build -ldflags "$(LDFLAGS)" -o bin/mcp-opnsense ./cmd/mcp-opnsense
	go build -ldflags "$(LDFLAGS)" -o bin/terraform-provider-opnsense ./cmd/terraform-provider-opnsense

test:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run

install-tf:
	go install -ldflags "$(LDFLAGS)" ./cmd/terraform-provider-opnsense

clean:
	rm -rf bin

