# Contributing to Kroxy

Thank you for your interest in contributing to Kroxy! This document provides guidelines and instructions for contributing.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to security@kroxy.dev.

## Development Setup

### Prerequisites

| Tool | Minimum Version | Required For | How to Install |
|------|-----------------|--------------|----------------|
| Go | 1.22+ | Building, testing | [go.dev](https://go.dev/dl/) |
| golangci-lint | 1.57+ | Linting | `curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \| sh -s -- -b $(go env GOPATH)/bin v1.57.2` |
| SQLite3 | 3.35+ | Local database | System package manager |
| Docker | 24.0+ | Container builds | [docker.com](https://docs.docker.com/get-docker/) |
| Make | Any | Build automation | System package manager |

**Verify your setup:**
```bash
go version             # Should show 1.22+
golangci-lint version  # Should show 1.57+
docker --version       # Optional for local container testing
```

### Getting Started

```bash
# Clone the repository
git clone git@github.com:MexxiUK/kroxy.git
cd kroxy

# Install dependencies
go mod download

# Verify modules
go mod verify

# Build
go build -o kroxy ./cmd/kroxy

# Run tests
go test ./...

# Run locally (development defaults)
./kroxy --listen :9080 --admin :9081 --db ./kroxy.db
```

### Using Makefile

```bash
make build    # Build the binary
make test     # Run all tests
make lint     # Run linter
make run      # Run with development defaults
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KROXY_LISTEN` | `:443` | Proxy listen address |
| `KROXY_ADMIN` | `:8080` | Admin API listen address |
| `KROXY_DB` | `./kroxy.db` | SQLite database path |

## Development Workflow

### 1. Create a Branch
```bash
git checkout -b feature/your-feature-name
```

### 2. Make Changes
- Follow the existing code style
- Add tests for new functionality
- Update documentation if needed

### 3. Test Your Changes
```bash
# Run all tests
go test ./...

# Run specific package tests
go test ./internal/auth/...

# Run with coverage
go test -cover ./...

# Run linter (required)
golangci-lint run ./...

# Run vulnerability check
govulncheck ./...
```

### 4. Commit Your Changes

We follow [Conventional Commits v1.0.0](https://www.conventionalcommits.org/en/v1.0.0/).

**Format:**
```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

**Types:**
| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `refactor` | Code change without fix/feature |
| `test` | Adding/updating tests |
| `chore` | Build, CI, or dependency changes |
| `perf` | Performance improvement |
| `security` | Security-related changes |

**Scopes:**
`api`, `auth`, `proxy`, `waf`, `store`, `middleware`, `validation`, `docs`, `ci`

**Examples:**
```bash
git commit -m "feat(auth): add OIDC logout endpoint"
git commit -m "fix(waf): prevent false positive on SQL injection rule"
git commit -m "security(store): hash API keys with bcrypt"
git commit -m "docs: update README deployment examples"

# Breaking change
git commit -m "feat(api)!: change route API response format

BREAKING CHANGE: Route API now returns 'id' as string instead of int"
```

### 5. Push and Create PR
```bash
git push origin feature/your-feature-name
```

## Code Style

### Go
- Follow [Effective Go](https://golang.org/doc/effective_go) and [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- Run `gofmt -s -w .` before committing
- Run `goimports -w .` to organize imports
- **Required:** Run `golangci-lint run ./...` and fix all issues before PR submission

### Security-Specific Guidelines
- **Never** commit secrets, passwords, or API keys
- Use `bcrypt` for password hashing (cost >= 12)
- Use parameterized queries for all database operations
- Add input validation for all user-facing APIs
- Log security-relevant events via the audit logger
- Run `govulncheck ./...` before submitting PRs

### General
- Keep functions focused and small (<50 lines preferred)
- Add godoc comments for all exported functions/types
- Use meaningful variable names (avoid single-letter except loop indices)
- Handle errors explicitly (no ignored errors)

### Pre-commit Hook (Optional)

```bash
# Install pre-commit hook
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/sh
gofmt -s -l . | grep -q . && echo "Run gofmt" && exit 1
go mod verify
go test ./...
golangci-lint run ./...
EOF
chmod +x .git/hooks/pre-commit
```

## Project Structure

```
kroxy/
├── cmd/kroxy/          # Main application entry point
├── internal/
│   ├── api/            # REST API handlers (routes, WAF, certs)
│   ├── auth/           # Authentication (OIDC, API keys, sessions)
│   ├── proxy/          # Reverse proxy core logic
│   ├── waf/            # WAF implementation (Coraza wrapper)
│   ├── store/          # Database layer (SQLite)
│   ├── validation/     # Input validation utilities
│   └── middleware/     # HTTP middleware (logging, auth)
├── web/                # Frontend assets (admin dashboard)
├── scripts/            # Deployment scripts (Docker, systemd)
├── docs/               # Documentation
└── .github/            # GitHub Actions workflows, issue templates
```

## Security Considerations

When contributing code:
- Never commit secrets, passwords, or API keys
- Validate all user inputs
- Use parameterized queries for database operations
- Follow security best practices for authentication/authorization
- Add appropriate logging for security-relevant events

## Pull Request Process

1. Create a feature branch from `main`
2. Make your changes following the code style guidelines
3. Run tests and linter: `make test && make lint`
4. Submit a pull request using the PR template
5. Ensure CI passes
6. Address any review feedback

## Issue Templates

We use templates for issues:
- **Bug Report**: Use `.github/ISSUE_TEMPLATE/bug_report.yml`
- **Feature Request**: Use `.github/ISSUE_TEMPLATE/feature_request.yml`
- **Security Issue**: Email security@kroxy.dev instead of creating an issue

## Questions?

Feel free to open an issue for:
- Bug reports
- Feature requests
- Documentation improvements
- Questions about the codebase

Thank you for contributing!