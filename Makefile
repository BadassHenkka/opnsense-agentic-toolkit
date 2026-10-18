VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all tidy test vet lint clean

all: vet test

tidy:
	go mod tidy

test:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run

clean:
	rm -rf bin

