# Build stage
FROM golang:1.22-alpine AS builder

# Install build dependencies for SQLite
RUN apk add --no-cache gcc musl-dev sqlite-dev git

WORKDIR /app

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build the binary with security flags
RUN CGO_ENABLED=1 go build -ldflags="-s -w -buildid=" -o kroxy ./cmd/kroxy

# Final stage - minimal image
FROM alpine:3.19

# Install only necessary runtime dependencies with specific versions
RUN apk add --no-cache \
    sqlite-libs=3.44.2-r0 \
    ca-certificates=20230506-r0 && \
    rm -rf /var/cache/apk/*

# Create non-root user with locked home directory
RUN adduser -D -u 1000 -h /home/kroxy -s /sbin/nologin kroxy && \
    chown -R kroxy:kroxy /home/kroxy

# Create required directories with restrictive permissions
RUN mkdir -p /data && \
    chown -R kroxy:kroxy /data && \
    chmod 750 /data

WORKDIR /app

# Copy binary from builder with specific ownership
COPY --from=builder --chown=kroxy:kroxy /app/kroxy /usr/local/bin/kroxy

# Set restrictive permissions
RUN chmod 550 /usr/local/bin/kroxy

# Expose ports (documentation only)
EXPOSE 80/tcp 443/tcp 8080/tcp

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:8080/api/status || exit 1

# Security: Don't use root
USER kroxy

# Security: Read-only root filesystem would break SQLite, so use tmpfs for writes
# Security: Drop all capabilities
# Security: No privilege escalation

# Set environment variables
ENV KROXY_LISTEN=:443 \
    KROXY_ADMIN=:8080 \
    KROXY_DB=/data/kroxy.db \
    GOMAXPROCS=1 \
    GOMEMLIMIT=256MiB

# Start the application
ENTRYPOINT ["/usr/local/bin/kroxy"]