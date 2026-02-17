VERSION ?= $(shell \
  TAG=$$(git tag -l "v*" | sort -V | tail -n 1); \
  [ -n "$$TAG" ] && echo $$TAG | sed 's/^v//' || echo 1.0.0 \
)

ROOT_DIR=../..

LDFLAGS = -w -s -X 'github.com/alapierre/godss/version.Version=$(VERSION)'

build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -a -installsuffix cgo .

windows:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)"

mac:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o qr-gen-darwin-arm64 .

clean:
	rm -f itrust-updater

.PHONY: gen build docker push clean
