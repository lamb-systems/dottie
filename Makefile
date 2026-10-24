GO ?= go
CC ?= cc
PKG_CONFIG ?= pkg-config
override GIO_MIN_VERSION := 2.40
GOTOOLCHAIN ?= local
export GOTOOLCHAIN CC PKG_CONFIG

.PHONY: build test test-race vet fmt fmt-check check verify fuzz fuzz-smoke native-check test-gnome test-gnome-race

FUZZ_TIME ?= 30s
FUZZ_SMOKE_TIME ?= 5s

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

verify:
	$(GO) mod verify
	$(GO) mod tidy -diff

fuzz:
	$(GO) test ./internal/model -run '^$$' -fuzz '^FuzzEntryValidate$$' -fuzztime=$(FUZZ_TIME)
	$(GO) test ./internal/model -run '^$$' -fuzz '^FuzzSnapshotValidate$$' -fuzztime=$(FUZZ_TIME)
	$(GO) test ./internal/config -run '^$$' -fuzz '^FuzzLoad$$' -fuzztime=$(FUZZ_TIME)

fuzz-smoke:
	$(GO) test ./internal/model -run '^$$' -fuzz '^FuzzEntryValidate$$' -fuzztime=$(FUZZ_SMOKE_TIME)
	$(GO) test ./internal/model -run '^$$' -fuzz '^FuzzSnapshotValidate$$' -fuzztime=$(FUZZ_SMOKE_TIME)
	$(GO) test ./internal/config -run '^$$' -fuzz '^FuzzLoad$$' -fuzztime=$(FUZZ_SMOKE_TIME)

native-check:
	@test "$$(uname -s)" = Linux || { echo "native GSettings tests require Linux" >&2; exit 1; }
	@test "$$($(GO) env CGO_ENABLED)" = 1 || { echo "native GSettings tests require CGO_ENABLED=1" >&2; exit 1; }
	@command -v $(CC) >/dev/null || { echo "native GSettings tests require a C compiler ($(CC))" >&2; exit 1; }
	@command -v $(PKG_CONFIG) >/dev/null || { echo "native GSettings tests require pkg-config" >&2; exit 1; }
	@$(PKG_CONFIG) --exists gio-2.0 || { echo "native GSettings tests require gio-2.0 development files" >&2; exit 1; }
	@$(PKG_CONFIG) --atleast-version=$(GIO_MIN_VERSION) gio-2.0 || { echo "native GSettings tests require GIO >= $(GIO_MIN_VERSION) (documentation-derived API floor)" >&2; exit 1; }
	@command -v glib-compile-schemas >/dev/null || { echo "native GSettings tests require glib-compile-schemas" >&2; exit 1; }
	@printf 'native prerequisites: Linux, CGO, %s, gio-2.0 %s (minimum %s), glib-compile-schemas\n' "$(CC)" "$$($(PKG_CONFIG) --modversion gio-2.0)" "$(GIO_MIN_VERSION)"

test-gnome: native-check
	$(GO) vet -tags gsettings ./internal/source/gnome
	$(GO) test -count=1 -tags gsettings ./internal/source/gnome

test-gnome-race: native-check
	$(GO) vet -tags gsettings ./internal/source/gnome
	$(GO) test -race -count=1 -tags gsettings ./internal/source/gnome
