# Build stage
FROM golang:1.25.9-alpine AS builder

# Build arguments for version embedding
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# Install build dependencies for SQLite
RUN apk add --no-cache gcc musl-dev sqlite-dev git

WORKDIR /app

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Ensure go.mod is consistent and build the binary
RUN go mod tidy && \
    CGO_ENABLED=1 go build \
    -ldflags="-s -w -buildid= -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildDate=${BUILD_DATE}" \
    -o kroxy ./cmd/kroxy

# Final stage - minimal image
FROM alpine:3.24.1

# Build arguments
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# OCI labels for container metadata
LABEL org.opencontainers.image.title="Kroxy" \
      org.opencontainers.image.description="Self-hosted reverse proxy with WAF and OIDC" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.source="https://github.com/kroxy/kroxy"

# Install only necessary runtime dependencies
RUN apk add --no-cache \
    sqlite-libs \
    ca-certificates \
    curl && \
    rm -rf /var/cache/apk/*

# Create non-root user with locked home directory
RUN adduser -D -u 1000 -h /home/kroxy -s /sbin/nologin kroxy && \
    chown -R kroxy:kroxy /home/kroxy

# Create required directories with restrictive permissions
RUN mkdir -p /data /data/certs /home/kroxy/.local/share/caddy && \
    chown -R kroxy:kroxy /data /home/kroxy && \
    chmod 750 /data

WORKDIR /app

# Copy binary from builder with specific ownership
COPY --from=builder --chown=kroxy:kroxy /app/kroxy /usr/local/bin/kroxy

# Set restrictive permissions
RUN chmod 550 /usr/local/bin/kroxy

# Expose ports (documentation only)
EXPOSE 80/tcp 443/tcp 8080/tcp

# Health check - use /ready for comprehensive health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://127.0.0.1:8080/ready || exit 1

# Security: Don't use root
USER kroxy

# Security: Read-only root filesystem would break SQLite, so use tmpfs for writes
# Security: Drop all capabilities
# Security: No privilege escalation

# Set environment variables
ENV KROXY_PROXY=:80 \
    KROXY_ADMIN=:8080 \
    KROXY_DB=/data/kroxy.db \
    GOMAXPROCS=1 \
    GOMEMLIMIT=256MiB

# Start the application
ENTRYPOINT ["/usr/local/bin/kroxy"]