VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
PREFIX ?= /usr/local

.PHONY: help build test vet fuzz docker install
help: ## List targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*## /\t/'
build: ## Build broker, broker-get, and broker-mcp into ./bin
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/ ./cmd/broker ./cmd/broker-get ./cmd/broker-mcp
test: ## Run all tests with the race detector
	go test -race -count=1 ./...
vet: ## go vet and gofmt check
	go vet ./...
	@test -z "$$(gofmt -l .)" || (gofmt -l .; exit 1)
fuzz: ## Fuzz the request parser for 30 s
	go test -run=NONE -fuzz=FuzzParseRequest -fuzztime=30s ./internal/contract
docker: ## Build the Docker image
	docker build --build-arg VERSION=$(VERSION) -t bw2fabroker:local .
install: build ## Install binaries, systemd unit, and sysusers entry (run as root)
	install -m 0755 bin/broker bin/broker-get bin/broker-mcp $(PREFIX)/bin/
	install -m 0644 deploy/systemd/bw2fabroker.service /etc/systemd/system/
	install -m 0644 deploy/systemd/bw2fabroker.sysusers /usr/lib/sysusers.d/bw2fabroker.conf
	install -d -m 0700 /etc/bw2fabroker
	systemd-sysusers
	chown broker:broker /etc/bw2fabroker
	@echo "Next: see README, Install (app mode)"
