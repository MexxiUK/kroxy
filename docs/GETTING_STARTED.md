# Getting Started with Kroxy

This guide walks you through deploying Kroxy, creating your first route, and enabling the Web Application Firewall (WAF) in under 5 minutes.

---

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/)
- A domain name pointing to your server (for HTTPS)
- Ports 80, 443, and 8080 available

---

## 1. Deploy with Docker Compose (Recommended)

Create a `docker-compose.yml`:

```yaml
services:
  kroxy:
    image: kroxy/kroxy:latest
    container_name: kroxy
    restart: unless-stopped
    ports:
      - "80:80"      # HTTP traffic
      - "443:443"    # HTTPS traffic
      - "127.0.0.1:8080:8080"  # Admin dashboard (localhost-only by default)
    volumes:
      - kroxy-data:/data
    environment:
      - KROXY_ADMIN=127.0.0.1:8080
      - KROXY_DB=/data/kroxy.db
      - KROXY_PRODUCTION=true
      - KROXY_TLS_ENABLED=true
      - KROXY_AUTO_HTTPS=true
      - KROXY_ACME_EMAIL=admin@example.com
      - KROXY_ENCRYPTION_KEY=CHANGE_ME_BASE64_32_BYTE_MINIMUM
      - KROXY_JWT_SECRET=CHANGE_ME_32_CHAR_MINIMUM
      - KROXY_WAF_SIGNING_KEY=CHANGE_ME_BASE64_32_BYTE_MINIMUM
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 512M

volumes:
  kroxy-data:
```

> **Security note:** `KROXY_ENCRYPTION_KEY` and `KROXY_WAF_SIGNING_KEY` must be base64-encoded 32-byte values. Generate them with:
> ```bash
> openssl rand -base64 32
> ```

Start Kroxy:

```bash
docker compose up -d
```

Wait for the health check to pass (usually within 15 seconds):

```bash
curl -f http://localhost:8080/ready
```

---

## 2. First-Time Setup

Open the admin panel in your browser:

```
http://localhost:8080/setup
```

> **Note:** The admin API binds to `127.0.0.1:8080` by default for security. Access it via SSH tunnel or from the server directly:
> ```bash
> ssh -L 8080:localhost:8080 your-server
> ```

The setup wizard will guide you through:

1. **Use case** — Personal, Business, or API Gateway
2. **Security level** — Recommended protection, custom rules, or skip for now
3. **First route** — Connect your domain to a backend service (optional; you can skip and add later)
4. **Admin authentication** — Choose:
   - **Authenticator App (TOTP)** — Google Authenticator, Authy, etc.
   - **Single Sign-On (OIDC)** — Google, Microsoft, or a custom provider
   - **Password Only** — For local network use only
5. **Create account** — Enter your name, email, and a strong password (minimum 12 characters)
6. **TOTP setup** (if selected) — Scan the QR code and enter the 6-digit verification code

After setup, you'll see a summary and a link to the dashboard.

---

## 3. Create Your First Route

A **route** tells Kroxy which domain to listen on and where to send the traffic.

1. Go to **Routes → Add Route** in the sidebar.
2. Fill in the form:
   - **Domain** — `api.example.com`
   - **Backend** — `http://localhost:3000` (or your app's URL)
   - **WAF** — Toggle on to enable the firewall
   - **Rate Limit** — Set requests per minute (e.g., `60`)
3. Click **Save**.

Kroxy will automatically reload its configuration. Within seconds, traffic to `api.example.com` will be proxied to your backend.

---

## 4. Enable Automatic HTTPS (Let's Encrypt)

If you started Kroxy with `KROXY_AUTO_HTTPS=true` and `KROXY_ACME_EMAIL`, HTTPS is already enabled for any route with a public domain. No additional steps are required.

To verify:

```bash
curl -I https://api.example.com
```

You should see `HTTP/2 200` and a valid certificate.

### Using Manual Certificates

If you prefer to use your own certificate:

1. Place `cert.pem` and `key.pem` in `/data/certs/` inside the container.
2. Set the environment variables:
   ```yaml
   environment:
     - KROXY_TLS_ENABLED=true
     - KROXY_AUTO_HTTPS=false
     - KROXY_TLS_CERT=/data/certs/cert.pem
     - KROXY_TLS_KEY=/data/certs/key.pem
   ```
3. Restart the container.

---

## 5. Enable the WAF

The Web Application Firewall is powered by the **OWASP Core Rule Set v4**.

### Global WAF (applies to all routes)

1. Go to **Security → WAF Rules**.
2. Toggle **Enable Global WAF**.
3. Set the **Paranoia Level**:
   - **1** — Minimal false positives (recommended for most sites)
   - **2** — Balanced security
   - **3–4** — Aggressive blocking (may block legitimate traffic)

### Per-Route WAF

1. Go to **Routes** and click the route you want to protect.
2. Toggle **WAF Enabled**.
3. Choose **Mode**:
   - **Block** — Reject malicious requests (HTTP 403)
   - **Detect** — Log but allow the request through
4. Save the route.

### Custom Rules

You can add custom WAF rules for specific threats:

1. In **WAF Rules**, click **Add Rule**.
2. Enter a name and a ModSecurity rule string, e.g.:
   ```
   SecRule ARGS "(?i)(union\s+select|select\s+.*\s+from)" "deny,log,msg:'SQL Injection Detected'"
   ```
3. Choose whether the rule applies to a specific route or globally.
4. Enable the rule and save.

---

## 6. Test the WAF

Send a malicious request to verify blocking:

```bash
curl -I "https://api.example.com/search?q=1' OR '1'='1"
```

Expected response: `HTTP/2 403`

Check the dashboard or **Security → Security Events** to see the blocked event.

---

## 7. Add Admin Users

1. Go to **Users** in the sidebar.
2. Click **Add User**.
3. Enter the email and assign a role:
   - **Admin** — Full access to all settings
   - **User** — Can view routes and logs, but cannot modify settings
4. The new user will receive (or be given) a setup link to set their password.

---

## 8. Backup Your Configuration

Before making major changes, export your configuration:

1. Go to **Monitoring → Backup & Restore**.
2. Click **Export Configuration**.
3. Save the JSON file securely.

The export includes all routes, WAF rules, users, and certificates (metadata only — private keys are not exported).

To restore later, use the **Import** button on the same page.

---

## Next Steps

| Task | Location |
|------|----------|
| Configure OIDC (Google, Microsoft, Okta) | **Users → Sign-In Providers** |
| Set up IP allowlists / blocklists | **Security → IP Lists** |
| Adjust rate limits | **Security → Rate Limits** |
| Monitor backend health | **Monitoring → Health Checks** |
| View access logs | **Monitoring → Access Logs** |
| Manage API keys for automation | **Users → API Keys** |

---

## Environment Variables

See [`.env.example`](../.env.example) for a complete reference of all supported environment variables.

---

## Troubleshooting

### Admin panel is not accessible

- Verify the admin port is bound correctly. By default it is `127.0.0.1:8081` (inside the container). In the compose example above it is changed to `127.0.0.1:8080`.
- Check Docker port mapping: `docker compose ps`.
- Review logs: `docker compose logs -f kroxy`.

### Certificate not issued

- Ensure your domain's DNS A/AAAA record points to the server's public IP.
- Ensure ports 80 and 443 are open to the internet (Let's Encrypt validates via HTTP-01).
- Check the container logs for ACME errors.

### WAF blocks legitimate requests

- Lower the **Paranoia Level** to `1`.
- Switch the route's WAF mode to **Detect** to observe without blocking.
- Add the client's IP to the **Allowlist** in **Security → IP Lists**.

### Database is locked

- Ensure only one Kroxy instance is using the same database file.
- SQLite WAL mode is used by default; do not delete `*.db-wal` or `*.db-shm` files while Kroxy is running.

---

**Need more help?** Open an issue on [GitHub](https://github.com/kroxy/kroxy/issues).
