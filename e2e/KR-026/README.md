# KR-026 — Admin Sidebar Regression Test Plan

## Issue

Authenticated admin pages rendered without the left sidebar navigation menu. Users could only see the page content and had no way to navigate between Dashboard, Routes, Security, Users, Settings, and Monitoring sections.

## Root cause

`web/templates/layouts/base.html` emitted the pre-rendered page content directly via `{{ .Content }}`. The sidebar, navbar, and main-content wrapper live in the `"content"` template defined in `web/templates/layouts/auth.html`, but that template was never invoked.

## Fix

`web/templates/layouts/base.html` now invokes `{{ template "content" . }}`, so every authenticated page renders inside the auth layout shell.

## How to verify the fix in the UI

These steps confirm the sidebar is present, functional, and wraps page content correctly.

### Prerequisites

1. Deploy the build containing the fix.
2. Have an admin account with 2FA set up.
3. If testing against CT112, use the values from the deployment notes; otherwise set:
   ```bash
   export KROXY_BASE_URL=http://10.1.0.112:18081   # or your test instance
   export KROXY_ADMIN_EMAIL=admin@example.com
   export KROXY_ADMIN_PASSWORD=Kroxy-admin1!
   export KROXY_ADMIN_TOTP_SECRET=<secret>
   ```

### Manual verification

#### 1. Dashboard page

1. Log in as an admin.
2. Navigate to `/dashboard`.
3. Confirm the page shows:
   - A left sidebar on the left with the Kroxy logo at the top.
   - Navigation sections: **Routes**, **Security**, **Users**, **Settings**, **Monitoring**.
   - A top navbar with a hamburger toggle and a user menu on the right.
   - The dashboard metrics cards (Live Traffic, Attacks Blocked, Route Health) inside a white content area to the right of the sidebar, not spanning the full window width.

#### 2. Other authenticated pages

Visit each admin route and confirm the sidebar and navbar remain visible and the page content sits inside the main panel:

- `/routes`
- `/routes/new`
- `/security/waf`
- `/security/ip-lists`
- `/security/rate-limits`
- `/security/events`
- `/users`
- `/users/api-keys`
- `/users/oidc`
- `/settings`
- `/settings/ssl`
- `/health-checks`
- `/logs`
- `/backup`
- `/profile`

On every page you should see:
- The sidebar is present and not empty.
- The active page's nav item is highlighted.
- The user menu in the navbar shows the admin's name/avatar initial.

#### 3. Sidebar navigation works

From any authenticated page:
1. Click a different sidebar item, e.g., **WAF Rules**.
2. Confirm the browser navigates to `/security/waf` and the WAF page content loads.
3. Confirm the active highlight moves to the selected item.

#### 4. Responsive behavior

1. With the browser viewport wider than `768px`, confirm the sidebar is visible by default.
2. Shrink the viewport to `768px` or below (or use DevTools mobile emulation).
3. Confirm the sidebar is hidden and a hamburger button appears in the navbar.
4. Click the hamburger button and confirm the sidebar slides in.
5. Click the backdrop or press `Escape` and confirm the sidebar closes.

#### 5. User menu

1. Click the user menu button in the navbar.
2. Confirm a dropdown appears with links to **Profile**, **API Keys**, and **Sign out**.
3. Click **Profile** and confirm navigation to `/profile` with the sidebar still visible.

#### 6. Public pages are unaffected

Visit these pages while logged out:

- `/login`
- `/setup`

Confirm they render as standalone pages without the admin sidebar or navbar.

### Automated verification

Run the existing smoke suite, which now includes sidebar coverage implicitly through page-load assertions:

```bash
cd e2e
export KROXY_BASE_URL=http://10.1.0.112:18081
export KROXY_ADMIN_EMAIL=admin@example.com
export KROXY_ADMIN_PASSWORD=Kroxy-admin1!
export KROXY_ADMIN_TOTP_SECRET=<secret>
npx playwright test tests/smoke.spec.js --project=chromium-desktop --retries=1 --workers=1
```

Expected result: all authenticated pages pass with no HTTP errors or unexpected console errors.

### Unit verification

The Go unit test added in `internal/api/api_test.go` renders the dashboard template and asserts:

- `<aside class="sidebar">` is present.
- `<nav class="sidebar-nav">` is present.
- `<nav class="navbar">` is present.
- `<main class="main-content">` is present.
- The dashboard page title appears inside `<main class="main-content">`.

Run it locally:

```bash
go test ./internal/api/... -run TestRenderTemplate_AuthenticatedPageIncludesSidebar -v
```

### What to report if it fails

If the sidebar is still missing on any page:
1. Note the exact route.
2. Capture a full-page screenshot or DOM dump.
3. Check whether the response contains `<aside class="sidebar">` or `<main class="main-content">`.
4. Report the route and whether the issue affects all pages or only specific ones.
