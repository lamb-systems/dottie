GO ?= go
CC ?= cc
PKG_CONFIG ?= pkg-config
override GIO_MIN_VERSION := 2.40
GOTOOLCHAIN ?= local
export GOTOOLCHAIN CC PKG_CONFIG

.PHONY: build test test-race vet fmt fmt-check check verify fuzz fuzz-smoke native-check test-gnome test-gnome-race known-defects acceptance

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

override KNOWN_DEFECTS_VAULT_TESTS := TestExpectedRefusalEnrollmentParentJoin TestExpectedRefusalCheckpointSkippedPolicyChain TestExpectedRefusalEnrollmentDeltaPolicyFields TestExpectedRefusalRevocationDeltaPolicyFields TestExpectedRefusalCheckpointCertPolicyRole TestExpectedRefusalPolicyDecoderOutOfRangeBounds TestCaseMatrixMatchesRefusalTests TestCaseSecurityGateIsClosed
override KNOWN_DEFECTS_ATPROTO_TESTS := TestExpectedRefusalReaderHeadEnvelopeParentLink TestExpectedRefusalReaderExtraRecipientInMetadata TestExpectedRefusalReaderUnauthorizedWrap TestExpectedRefusalReaderOlderSnapshotAtNextCount TestExpectedRefusalReaderCoherentForkBehindHead TestExpectedRefusalReaderSplitHeadAndEnvelopeSigners TestExpectedRefusalReaderControlAncestry TestExpectedRefusalReaderHeadAboveMaxPublications TestCaseMatrixMatchesRefusalTests TestCaseSecurityGateIsClosed

known-defects:
	@set +e; \
	tmpdir="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	$(GO) test -count=1 -v -tags known_defects ./internal/vault >"$$tmpdir/vault.log" 2>&1; vault_status=$$?; \
	cat "$$tmpdir/vault.log"; \
	$(GO) test -count=1 -v -tags known_defects ./internal/remote/atproto >"$$tmpdir/atproto.log" 2>&1; atproto_status=$$?; \
	cat "$$tmpdir/atproto.log"; \
	check_names() { \
		log="$$1"; shift; missing=0; \
		for name in "$$@"; do \
			if ! grep -Eq "^--- (PASS|FAIL): $$name([[:space:]]|$$)" "$$log"; then \
				printf 'known-defects: missing PASS/FAIL result for %s\n' "$$name" >&2; missing=1; \
			fi; \
		done; \
		return "$$missing"; \
	}; \
	guard_status=0; \
	check_names "$$tmpdir/vault.log" $(KNOWN_DEFECTS_VAULT_TESTS) || guard_status=1; \
	check_names "$$tmpdir/atproto.log" $(KNOWN_DEFECTS_ATPROTO_TESTS) || guard_status=1; \
	if [ "$$guard_status" -ne 0 ]; then exit 1; fi; \
	if [ "$$vault_status" -ne 0 ] || [ "$$atproto_status" -ne 0 ]; then exit 1; fi

acceptance: check test-race build known-defects

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
	@command -v dbus-run-session >/dev/null || { echo "native GNOME restore gate requires dbus-run-session" >&2; exit 1; }
	@command -v gsettings >/dev/null || { echo "native GNOME restore gate requires gsettings" >&2; exit 1; }
	@tmpfile="$$(mktemp)"; trap 'rm -f "$$tmpfile"' EXIT; \
	if ! GSETTINGS_BACKEND=dconf gsettings list-schemas >/dev/null 2>"$$tmpfile"; then \
		cat "$$tmpfile" >&2; echo "native GNOME restore gate requires a loadable dconf GIO backend (install the dconf GSettings backend)" >&2; exit 1; \
	fi; \
	if grep -Fq "Can't find module" "$$tmpfile"; then \
		cat "$$tmpfile" >&2; echo "native GNOME restore gate could not load the dconf GIO module" >&2; exit 1; \
	fi
	@printf 'native prerequisites: Linux, CGO, %s, gio-2.0 %s (minimum %s), glib-compile-schemas, dbus-run-session, loadable dconf GIO module. The probe proves loadability only; the isolated gate proves write and activation.\n' "$(CC)" "$$($(PKG_CONFIG) --modversion gio-2.0)" "$(GIO_MIN_VERSION)"

test-gnome: native-check
	$(GO) vet -tags gsettings ./internal/source/gnome ./tests/local
	$(GO) test -count=1 -tags gsettings ./internal/source/gnome
	$(GO) test -count=1 -tags gsettings ./tests/local

test-gnome-race: native-check
	$(GO) vet -tags gsettings ./internal/source/gnome ./tests/local
	$(GO) test -race -count=1 -tags gsettings ./internal/source/gnome
	$(GO) test -race -count=1 -tags gsettings ./tests/local
