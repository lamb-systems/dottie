GO ?= go
GOTOOLCHAIN ?= local
export GOTOOLCHAIN

.PHONY: build test test-race vet fmt fmt-check check

build:
	$(GO) build -trimpath -o bin/dottie ./cmd/dottie

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w cmd internal

fmt-check:
	@files="$$(gofmt -l cmd internal)"; \
	if [ -n "$$files" ]; then printf 'Run make fmt for:\n%s\n' "$$files"; exit 1; fi

check: fmt-check vet test
