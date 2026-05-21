# Kroxy Production-Readiness Deployment & Operations Audit Report

**Scope:** Deployment artifacts, infrastructure, CI/CD, and operational readiness

---

## Critical Deployment Blockers

### 1. Missing `.dockerignore` — secrets and artifacts baked into images
- **File:** `/run/media/david-lee/SabrentRAID/Projects/kroxy/Dockerfile` (line 19: `COPY . .`)
- **Impact:** The repository contains untracked but present sensitive files and build artifacts that Docker will copy into the image:
  - `kroxy` — 86 MB production binary in repo root
  - `internal/auth/.kroxy-encryption-key` — 45-byte encryption key
  - `internal/store/.kroxy-encryption-key` — 45-byte encryption key
  - `data/audit.log` — audit logs
- **Fix:** Create a `.dockerignore` that excludes `.git*`, `*.key`, `*.pem`, `.kroxy-encryption-key`, `data/`, `bin/`, `dist/`, `kroxy`, and other non-build artifacts.

### 2. Kubernetes secrets committed with placeholder values
- **File:** `/run/media/david-lee/SabrentRAID/Projects/kroxy/deploy/k8s/secret.yaml` (lines 10-26)
- **Impact:** Placeholder secrets (`CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_BASE64_32`, `CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_HEX_32`) are committed to git. If deployed without change, the application runs with predictable credentials.
- **Fix:** Replace with external-secrets/SealedSecrets references, or add a `kustomize` patch overlay and document that `secret.yaml` must be generated locally and never committed.

### 3. Systemd service unit uses wrong environment variable
- **File:** `/run/media/david-lee/SabrentRAID/Projects/kroxy/scripts/kroxy.service` (line 18)
- **Impact:** `Environment=KROXY_LISTEN=:443` is set, but the application reads `KROXY_PROXY` (confirmed in `/run/media/david-lee/SabrentRAID/Projects/kroxy/internal/config/config.go:91`). The proxy will silently fall back to `:80`, causing a misconfiguration on systemd deployments.
- **Fix:** Change `KROXY_LISTEN` to `KROXY_PROXY`.

### 4. Docker Compose health check endpoint is a status stub, not readiness
- **File:** `/run/media/david-lee/SabrentRAID/Projects/kroxy/docker-compose.yml` (line 60)
- **Impact:** The health check hits `/api/status`, which is a lightweight version/status stub. It does **not** verify database connectivity. In production, an unhealthy database will not be detected by the health check.
- **Fix:** Change to `/ready` (the actual readiness probe that pings the database), consistent with `docker-compose.secure.yml` and the Dockerfile.

---

## High Priority Hardening Items

### 5. CI pipeline does not fail on Trivy findings
- **File:** `/run/media/david-lee/SabrentRAID/Projects/kroxy/.github/workflows/ci.yml` (lines 204-212)
- **Impact:** Trivy scans for CRITICAL/HIGH vulnerabilities but the command lacks `--exit-code 1`, so findings never block the build.
- **Fix:** Add `--exit-code 1` to the Trivy invocation, or pipe results to a step that fails on detections.

### 6. CI pipeline mounts Docker socket unnecessarily
- **File:** `/run/media/david-lee/SabrentRAID/Projects/kroxy/.github/workflows/ci.yml` (line 206)
- **Impact:** `-v /var/run/docker.sock:/var/run/docker.sock` gives the Trivy container full Docker daemon access. This is a privileged escalation risk.
- **Fix:** Use `aquasec/trivy` in standalone filesystem mode (`trivy fs .` or `trivy image --input`) without mounting the socket, or use the `trivy-action` GitHub Action.

### 7. `docker-compose.secure.yml` disables seccomp
- **File:** `/run/media/david-lee/SabrentRAID/Projects/kroxy/docker-compose.secure.yml` (line 29)
- **Impact:** `seccomp=unconfined` removes the seccomp syscall filter, significantly reducing container isolation.
- **Fix:** Remove this line. If SQLite truly needs a specific syscall, whitelist it with a custom seccomp profile rather than disabling the entire filter.

### 8. Init container uses mutable `busybox:latest` tag
- **File:** `/run/media/david-lee/SabrentRAID/Projects/kroxy/deploy/k8s/deployment.yaml` (line 39)
- **Impact:** `busybox:latest` is mutable. A compromised or updated image could alter permissions unexpectedly.
- **Fix:** Pin to a specific digest (e.g., `busybox:1.36.1-uclibc@sha256:...`).

### 9. `docker-compose.yml` and `.secure.yml` use static container IP assignments
- **Files:** `/run/media/david-lee/SabrentRAID/Projects/kroxy/docker-compose.yml` (lines 49, 91), `docker-compose.secure.yml` (lines 34, 93)
- **Impact:** Hardcoded static IPs (`172.28.0.2`, `172.20.0.2`) create conflicts and fragility in multi-environment deployments.
- **Fix:** Remove `ipv4_address` and use DNS-based service discovery.

### 10. `DEPLOYMENT.md` shows insecure direct-build-on-LXC workflow
- **File:** `/run/media/david-lee/SabrentRAID/Projects/kroxy/DEPLOYMENT.md` (lines 37-67)
- **Impact:** Instructions copy source via SCP to Proxmox, build inside the LXC, and run `docker run` without `--read-only`, `--user`, or `--cap-drop`. The bind mount `-v /root/kroxy.db:/data/kroxy.db` uses `/root` on the host, violating least-privilege.
- **Fix:** Replace with a registry-based pull workflow (build once, push to GHCR, pull on host). Add security flags matching the compose file.

### 11. `docker-compose.yml` runs in development mode by default
- **File:** `/run/media/david-lee/SabrentRAID/Projects/kroxy/docker-compose.yml` (lines 44-45)
- **Impact:** `KROXY_PRODUCTION=false` and `KROXY_ALLOW_PRIVATE_BACKENDS=true` are set without warning. This enables unsafe defaults for what may be treated as a production compose file.
- **Fix:** Remove `KROXY_ALLOW_PRIVATE_BACKENDS` entirely (defaults to `false`). Set `KROXY_PRODUCTION=true` or add a large warning comment.

### 12. `docker-compose.secure.yml` contains a hardcoded ACME email placeholder
- **File:** `/run/media/david-lee/SabrentRAID/Projects/kroxy/docker-compose.secure.yml` (line 49)
- **Impact:** `KROXY_ACME_EMAIL=admin@example.com` will be sent to Let's Encrypt if the user forgets to change it.
- **Fix:** Leave it empty with a comment, and let the application fail fast on validation.

---

## Medium Priority Improvements

### 13. Alpine base image is outdated
- **File:** `/run/media/david-lee/SabrentRAID/Projects/kroxy/Dockerfile` (line 28)
- **Impact:** `alpine:3.19` is aging. While not yet EOL, newer Alpine versions have additional security patches and musl improvements.
- **Fix:** Upgrade to `alpine:3.20` or `alpine:3.21`.

### 14. Dockerfile installs `curl` just for the health check
- **File:** `/run/media/david-lee/SabrentRAID/Projects/kroxy/Dockerfile` (lines 46-47)
- **Impact:** Increases attack surface by ~7 MB and adds a network-capable binary.
- **Fix:** Use a compiled Go health check, or copy a static `wget`/`curl` binary, or use the `HEALTHCHECK CMD` with `/proc/net/tcp` parsing if feasible. Alternatively, accept the trade-off but document it.

### 15. Go release builds in `Makefile` disable CGO; Docker enables CGO
- **File:** `/run/media/david-lee/SabrentRAID/Projects/kroxy/Makefile` (lines 43-52)
- **Impact:** `make release` sets `CGO_ENABLED=0` but the Dockerfile sets `CGO_ENABLED=1` (required for SQLite). Cross-compiled releases may behave differently or fail to support SQLite.
- **Fix:** Document that official releases require CGO and use `zig cc` or a cross-compilation container. Alternatively, remove unsupported release targets and rely on Docker builds.

### 16. Missing `seccompProfile` and `drop ALL` in Docker Compose compared to K8s
- **Note:** The K8s manifest has excellent hardening (`runAsNonRoot: true`, `seccompProfile: RuntimeDefault`, `readOnlyRootFilesystem: true`, `capabilities: drop: ALL`). The Docker Compose files have `cap_drop: ALL` and `read_only: true`, which is good, but lack `seccomp` enforcement (except the `.secure.yml` which disables it).
- **Fix:** Add a custom seccomp profile to compose files.

### 17. No resource limits in the `docker` service of example compose files
- **Files:** `docs/examples/docker-compose.*.yml`
- **Impact:** Examples don't show resource limits, encouraging unbounded deployments.
- **Fix:** Add `deploy.resources.limits` blocks to all examples.

### 18. `Makefile` uses legacy `docker-compose` command
- **File:** `/run/media/david-lee/SabrentRAID/Projects/kroxy/Makefile` (lines 37, 40)
- **Impact:** `docker-compose` (v1) is deprecated. `docker compose` (v2) is standard.
- **Fix:** Update commands.

### 19. CI `gosec` is non-blocking
- **File:** `/run/media/david-lee/SabrentRAID/Projects/kroxy/.github/workflows/ci.yml` (line 90)
- **Impact:** `gosec ... || true` silently ignores security findings.
- **Fix:** Remove `|| true`, fix or explicitly suppress remaining findings with justification comments.

### 20. Semgrep action is deprecated
- **File:** `/run/media/david-lee/SabrentRAID/Projects/kroxy/.github/workflows/ci.yml` (line 93)
- **Impact:** `returntocorp/semgrep-action@v1` is deprecated. The current action is `semgrep/semgrep`.
- **Fix:** Update to `semgrep/semgrep-action` or `semgrep/semgrep`.

### 21. K8s ingress backend uses plain HTTP internally
- **File:** `/run/media/david-lee/SabrentRAID/Projects/kroxy/deploy/k8s/ingress.yaml` (lines 30-35)
- **Impact:** Traffic between ingress-nginx and the `kroxy` service on port 80 is unencrypted inside the cluster.
- **Fix:** Consider an HTTPS backend or Istio/Linkerd mTLS for service mesh if cluster-level encryption is required. (Low severity if ingress and service are on the same node/overlay.)

---

## Operational Readiness Assessment

**Can this be deployed safely today?**
**Conditional No — blockers must be resolved first.**

The application itself has strong security fundamentals:
- Dockerfile runs as non-root (`USER kroxy`, UID 1000) ✅
- Graceful shutdown handles `SIGTERM` correctly (`px.Stop()`, `server.Shutdown(ctx)`) ✅
- Health checks (`/health`, `/ready`, `/healthz`) are implemented and wired in K8s manifests ✅
- Resource limits exist in K8s and Docker Compose ✅
- CI includes govulncheck, gosec (albeit non-blocking), and Semgrep ✅
- K8s manifests have good hardening (`readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, `runAsNonRoot`, `seccompProfile: RuntimeDefault`) ✅

However, **the build and distribution pipeline is not safe today** because:
1. Without a `.dockerignore`, images will contain encryption keys, audit logs, and an 86 MB untracked binary.
2. The systemd service unit references the wrong environment variable (`KROXY_LISTEN`), causing a silent config mismatch.
3. The `docker-compose.yml` health check uses a status stub instead of the real readiness probe, masking database failures.
4. Kubernetes `secret.yaml` ships with literal placeholder values that could be deployed unchanged.

**Recommended immediate actions before production deployment:**
1. Add `.dockerignore` (5-minute fix).
2. Fix `scripts/kroxy.service` env var name (1-minute fix).
3. Change `docker-compose.yml` health check to `/ready` (1-minute fix).
4. Replace K8s `secret.yaml` placeholders with generation instructions or external-secrets integration.
5. Make Trivy and gosec findings block CI builds.
