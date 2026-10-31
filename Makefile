VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test e2e clean

# Static Linux binaries. CGO is off, so they do not depend on the host's glibc
# and the same file runs on every supported Ubuntu release.
build:
	@mkdir -p dist
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/ubuntu-sys-audit-linux-amd64 .
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/ubuntu-sys-audit-linux-arm64 .
	cd dist && shasum -a 256 ubuntu-sys-audit-linux-* > SHA256SUMS

# Unit tests need Linux, so on macOS they run inside an Ubuntu container.
test:
	docker run --rm -v "$(CURDIR)":/src -w /src golang:1.27 go test ./...

# Boots each Ubuntu release in Docker, plants fake indicators and checks the
# detections. Takes several minutes.
e2e:
	sh test/e2e/run.sh

clean:
	rm -rf dist
