.PHONY: build build-client build-all run test lint clean

GATEWAY := dns2tcp-gateway
CLIENT := dns2tcp-client
PKG_GATEWAY := ./cmd/dns2tcp
PKG_CLIENT := ./cmd/dns2tcp-client
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X github.com/ohmymex/dns2tcp-gateway/internal/version.Version=$(VERSION) \
	-X github.com/ohmymex/dns2tcp-gateway/internal/version.Commit=$(COMMIT) \
	-X github.com/ohmymex/dns2tcp-gateway/internal/version.BuildDate=$(BUILD_DATE)

build:
	go build -ldflags "$(LDFLAGS)" -o $(GATEWAY) $(PKG_GATEWAY)

build-client:
	go build -ldflags "$(LDFLAGS)" -o $(CLIENT) $(PKG_CLIENT)

build-all: build build-client

run: build
	GATEWAY_DNS_ADDR=:5354 GATEWAY_API_ADDR=:8080 LOG_LEVEL=debug ./$(GATEWAY)

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

clean:
	rm -f $(GATEWAY) $(CLIENT)
	go clean -testcache
