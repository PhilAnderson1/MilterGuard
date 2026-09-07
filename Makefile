VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo development)

.PHONY: build test vet

build:
	CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/milterguard ./cmd/milterguard

test:
	go test ./...

vet:
	go vet -buildvcs=false ./...
