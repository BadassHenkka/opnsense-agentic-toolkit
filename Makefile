VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all gen gen-check fetch-models verify-upstream acc tidy build test vet lint install-tf clean

all: gen-check vet test build

# Regenerate zz_gen_*.go from gen/specs and gen/models.
gen:
	go run ./cmd/opnsense-gen

# Fail if generated code is out of date.
gen-check:
	go run ./cmd/opnsense-gen -check

# Download the model XML the specs use, at the commits in gen/models/REFS.
fetch-models:
	go run ./cmd/opnsense-gen -fetch

# Check every spec against the PHP API controllers at the pinned refs (needs network).
verify-upstream:
	go run ./cmd/opnsense-gen -verify

# Acceptance tests against a real firewall (OPNSENSE_URL/API_KEY/API_SECRET). Read-only;
# add OPNSENSE_ACC_WRITE=1 on a test VM to also create and delete acc-test-* objects.
acc:
	OPNSENSE_ACC=1 go test -count=1 -v ./internal/acceptance

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

