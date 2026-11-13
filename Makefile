# Builds prox with the git commit baked into the binary. The stamp lands
# in the "meta" event at the head of every captured stream's meta.jsonl
# and in the journal "starting" line, so each capture is traceable to the
# build that wrote it. Unstamped builds no longer report "dev" from
# `make`: the build refuses without a resolvable commit, and the CLI
# refuses to start on an empty or "dev" commit.
#
# NOTE: the unit runs /usr/local/bin/prox, so the production build must go
# through this target (or pass the same -X flag) or the service will
# refuse to start at runtime.

COMMIT  := $(shell git rev-parse --short=12 HEAD 2>/dev/null)
LDFLAGS := -X github.com/nicois/prox/pkg/version.Commit=$(COMMIT)

.PHONY: all test vet version

all:
	@test -n "$(COMMIT)" || { echo "fatal: unknown git commit: cannot stamp the build (not in a git checkout?)" >&2; exit 1; }
	go build -ldflags '$(LDFLAGS)' -o prox .

test:
	go test ./...

vet:
	go vet ./...

version:
	@echo $(COMMIT)
