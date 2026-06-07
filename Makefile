.PHONY: build run clean test test-race test-integration test-coverage test-validate lint security test-all pre-push docker docker-run docker-stop install release dev

VERSION := 1.0.0
BINARY := kroxy

# Minimum coverage thresholds per package (update as coverage improves)
COVERAGE_OVERALL := 20.0
COVERAGE_AUTH := 39.0
COVERAGE_STORE := 35.0
COVERAGE_WAF := 27.0
COVERAGE_SECURITY := 77.0
COVERAGE_VALIDATION := 36.0
COVERAGE_CRYPTO := 79.0
COVERAGE_TOTP := 88.0
COVERAGE_PROXY := 60.0

build:
	go build -o bin/$(BINARY) ./cmd/$(BINARY)

run:
	KROXY_PROXY=:9080 KROXY_ADMIN=:9081 go run ./cmd/$(BINARY)

clean:
	rm -rf bin/ kroxy.db coverage.out coverage.html

test:
	go test -v -count=1 ./...

test-race:
	go test -v -race -count=1 ./...

test-integration:
	go test -v -count=1 -tags=integration ./internal/api/...

test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Run all checks that execute quickly — intended for local pre-push validation
test-all: test-race test-integration lint security test-validate
	@echo "✅ All checks passed"

# Validate coverage against thresholds (adjust thresholds as coverage improves)
test-validate: coverage.out
	@echo "Checking coverage thresholds..."
	@overall=$$(go tool cover -func=coverage.out | grep "total:" | awk '{print $$3}' | tr -d '%'); \
	if [ $$(echo "$$overall < $(COVERAGE_OVERALL)" | bc -l) -eq 1 ]; then \
		echo "❌ Overall coverage $$overall% < $(COVERAGE_OVERALL)%"; exit 1; \
	fi; \
	echo "✅ Overall coverage: $$overall% (threshold: $(COVERAGE_OVERALL)%)"; \
	proxy=$$(go test -cover ./internal/proxy 2>&1 | grep -o 'coverage: [0-9.]*%' | sed 's/coverage: //;s/%//'); \
	if [ -n "$$proxy" ] && [ $$(echo "$$proxy < $(COVERAGE_PROXY)" | bc -l) -eq 1 ]; then \
		echo "❌ Proxy coverage $$proxy% < $(COVERAGE_PROXY)%"; exit 1; \
	fi; \
	if [ -n "$$proxy" ]; then echo "✅ Proxy coverage: $$proxy% (threshold: $(COVERAGE_PROXY)%)"; fi

coverage.out:
	go test -coverprofile=coverage.out ./...

lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "⚠️  golangci-lint not installed. Install from https://golangci-lint.run/"; \
		echo "   Falling back to go vet..."; \
		go vet ./...; \
	fi

security:
	@if command -v gosec >/dev/null 2>&1; then \
		gosec -exclude=G104,G307,G115 ./...; \
	else \
		echo "⚠️  gosec not installed. Install: go install github.com/securego/gosec/v2/cmd/gosec@latest"; \
		exit 1; \
	fi

pre-push: clean test-all
	@echo "🚀 Ready to push"

docker:
	docker build -t $(BINARY):latest .
	docker tag $(BINARY):latest $(BINARY):$(VERSION)

docker-run:
	docker compose up -d

docker-stop:
	docker-compose down

release: clean
	mkdir -p dist
	# Native binary (CGO required for SQLite)
	go build -ldflags="-s -w -X main.Version=$(VERSION)" -o dist/$(BINARY) ./cmd/$(BINARY)
	@echo "Binary built: dist/$(BINARY)"
	@echo "For cross-platform releases, use 'make release-docker'"

release-docker:
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		--build-arg VERSION=$(VERSION) \
		-t $(BINARY):$(VERSION) \
		-t $(BINARY):latest \
		--push \
		.

dev:
	KROXY_PROXY=:9080 KROXY_ADMIN=:9081 go run ./cmd/$(BINARY)
