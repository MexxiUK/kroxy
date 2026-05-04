.PHONY: build run clean test test-race test-integration test-coverage test-ci docker docker-run docker-stop install release dev

VERSION := 0.2.0
BINARY := kroxy

build:
	go build -o bin/$(BINARY) ./cmd/$(BINARY)

run:
	KROXY_PROXY=:9080 KROXY_ADMIN=:9081 go run ./cmd/$(BINARY)

clean:
	rm -rf bin/ kroxy.db

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

test-ci: test-race test-integration
	go test -coverprofile=coverage.out ./...

docker:
	docker build -t $(BINARY):latest .
	docker tag $(BINARY):latest $(BINARY):$(VERSION)

docker-run:
	docker-compose up -d

docker-stop:
	docker-compose down

install:
	sudo cp bin/$(BINARY) /usr/local/bin/$(BINARY)
	sudo mkdir -p /etc/$(BINARY) /var/lib/$(BINARY)
	sudo cp scripts/$(BINARY).service /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable $(BINARY)

release: clean
	# Linux AMD64
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=$(VERSION)" -o dist/$(BINARY)-linux-amd64 ./cmd/$(BINARY)
	# Linux ARM64
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=$(VERSION)" -o dist/$(BINARY)-linux-arm64 ./cmd/$(BINARY)
	# macOS AMD64
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=$(VERSION)" -o dist/$(BINARY)-darwin-amd64 ./cmd/$(BINARY)
	# macOS ARM64
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=$(VERSION)" -o dist/$(BINARY)-darwin-arm64 ./cmd/$(BINARY)
	# Windows
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=$(VERSION)" -o dist/$(BINARY)-windows-amd64.exe ./cmd/$(BINARY)

dev:
	KROXY_PROXY=:9080 KROXY_ADMIN=:9081 go run ./cmd/$(BINARY)
