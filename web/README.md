# access-hub portal

Frontend portal for **access-hub** (Go IAM): one **Company ID** (primary identity) that
reaches many per-app **workspace accounts**. Implemented as a single Next.js app in
`web/`, styled after the dark-teal login prototype (`--ah-bg: #093F3F`,
`--ah-accent: #54B3B3`).

## Stack

Mirrors `taskd/web`: Next.js 16 (App Router) + React 19 + TypeScript (strict) +
Tailwind CSS v4 + TanStack Query v5, driven by **bun**. The bespoke teal design
language uses a small hand-rolled component set (`components/`) instead of a UI kit.

## Run

The backend must be up on **:8080** first (repo root: `docker compose up -d` then run
`cmd/access-hub`).

```bash
cd web
bun install
bun run dev        # http://localhost:3000
```

The browser stays same-origin with the portal; `next.config.ts` rewrites
`/api/v1/*` to the backend:

- `ACCESS_HUB_API_URL` — backend base URL, default `http://localhost:8080`.
  Restart `bun run dev` after changing it.

Production build:

```bash
bun run build
bun run start      # same rewrite/proxy applies
```

The dev server listens on port **3000** (`PORT` env to change). `bun run lint` /
`bun run format` for ESLint / Prettier.

## Screens

| Route | Purpose | API calls |
|---|---|---|
| `/login` | Company ID sign-in, 2FA step, SSO `next` redirect, social provider buttons | `POST /auth/login`, `POST /auth/login/2fa`, `GET /auth/social/{provider}/start` |
| `/social/complete` | social provider callback landing (login + link modes) | `POST /auth/social/complete` |
| `/register` | Create Company ID, auto-login | `POST /auth/register` |
| `/forgot-password` | email → code → new password | `POST /auth/email/code`, `POST /auth/password/reset` |
| `/workspaces` | workspace picker ("Welcome back") | `GET /me/workspaces`, `POST /me/workspaces/{accountId}/token` |
| `/identity` | primary identity + 2FA status + connected accounts + linked accounts | `GET /me`, `GET /me/2fa/status`, `GET /me/workspaces`, `GET /me/social-identities`, `DELETE /me/social-identities/{id}` |
| `/identity/2fa` | TOTP enrollment wizard / 2FA management | `GET /me/2fa/status`, `POST /me/2fa/enroll`, `POST /me/2fa/confirm`, `POST /me/2fa/disable` |
| `/workspace/[accountId]` | workspace detail (access & role, sign-in methods) | `GET /me/workspaces/{accountId}`, `GET /me/signin-methods` |
| `/invite` | redeem invitation (works signed-in or anonymous) | `POST /invitations/redeem`, `POST /invitations/accept` |
| `/me/password` | change password | `PATCH /me` |

## Admin console (`/admin/*`, M6)

The admin console lives **inside the same portal app** at `/admin/*` (sidebar
shell under `src/components/admin/admin-shell.tsx`). It dogfoods the backend's
admin APIs with the **normal portal token** (`ah.access`): the server resolves
the caller's admin-app (`admin`) account + Casbin codes per request, so the
frontend never needs a separate admin session.

### Permission model

- Admin routes are enforced by `RequireAdmin(code)` with codes mirroring the
  API 1:1 (see `internal/api/admin_resources.go`).
- **Platform-only codes** — `admin:org:*`, `admin:user:*`, `admin:audit:*` —
  are never bound to org_admin. The orgs, users and audit sections render a
  "You don't have access to this section" placeholder card (`ForbiddenCard`)
  on 403 instead of an error; nav items stay visible and degrade gracefully.
- **App-scoped codes** — `admin:app:*`, `admin:account:*`,
  `admin:invitation:*`, `admin:resource:*`, `admin:role:*`, `admin:grant:*`,
  `admin:oauthclient:*` — are bound to org_admin and row-filtered to the
  org's apps server-side.
- `must_change_password` keeps blocking admin APIs; the portal banner is
  rendered in the admin shell too.

### Screens

| Route | Purpose | API calls |
|---|---|---|
| `/admin` | Overview: stat cards (apps/orgs counts, users total via `?page=1&page_size=1`) + audit summary (1/7/30-day CSS bar chart, top actions/actors) | `GET /admin/apps`, `GET /admin/orgs`, `GET /admin/users`, `GET /admin/audit-logs/summary` |
| `/admin/orgs` | org table + create/edit + per-org members drawer (add/remove, guard errors surfaced) | `GET/POST/PATCH /admin/orgs`, `GET/POST/DELETE /admin/orgs/{key}/members` |
| `/admin/apps` | app table + create/edit/disable | `GET/POST/PATCH /admin/apps` |
| `/admin/apps/{appKey}` | tabbed detail (tab in `?tab=`) | — |
| ↳ Resources | tree table (indent by depth, type chips, method+route), node create/edit (parent select), delete (children guard toast), JSON batch import panel with item count + `?mode=replace` double-confirm | `GET/POST/PATCH/DELETE .../resources`, `PUT .../resources:batch` |
| ↳ Roles | CRUD (built-in protected) + "bind resources" drawer: tree grouped by type with checkboxes and per-item allow/deny, submitted as `items:[{resource_id, effect}]` | `GET/POST/PATCH/DELETE .../roles`, `PUT .../roles/{id}/resources` |
| ↳ Accounts | provision (empty password → activation email note), enable/disable, reset password, transfer, set roles, direct-grants drawer (resource + optional expiry + effect) | `GET/POST .../accounts`, `PATCH .../accounts/{id}`, `POST .../accounts/{id}/reset-password` / `transfer`, `PUT .../accounts/{id}/roles`, `GET/POST/DELETE .../accounts/{id}/grants` |
| ↳ Invitations | list + create (email, roles, ttl_hours) + revoke | `GET/POST .../invitations`, `POST .../invitations/{id}/revoke` |
| ↳ OAuth clients | list + create/edit/delete; plaintext **secret shown exactly once** in a copyable callout (only its hash is stored) | `GET/POST .../oauth-clients`, `PATCH/DELETE .../oauth-clients/{clientId}` |
| ↳ Custom rules (M6) | expr rules (name/effect chip/priority/status) + create/edit form (invalid expr → backend 1400 message inline) + inline test panel (`obj`/`act` → allowed/denied result chip; dry-run, never saves) | `GET/POST/PATCH/DELETE .../custom-rules`, `POST .../custom-rules/test` |
| `/admin/users` | primary identities: search `?q=`, server-paged table, disable/enable, reset password | `GET /admin/users`, `PATCH /admin/users/{id}`, `POST /admin/users/{id}/reset-password` |
| `/admin/audit` | summary strip (reuse) + action/org_key filters + server-paged table with pretty-printed detail jsonb in expandable rows (IP/UA shown) | `GET /admin/audit-logs`, `GET /admin/audit-logs/summary` |

### Implementation notes

- All fetching rides TanStack Query (invalidate on mutations); every list has
  a loading skeleton, empty card and error toast; destructive actions use the
  inline two-step `ConfirmButton` (house style).
- New minimal shared components: `components/table.tsx` (sticky header, zebra
  rows, expandable rows), `components/tabs.tsx`, `components/dialog.tsx`,
  `components/drawer.tsx`, `components/confirm-button.tsx`,
  `components/form-fields.tsx` (select/textarea/checkbox-list matching
  `Field`), `components/admin/*` (shell, audit summary strip, effect/resource
  chips). No chart lib, no UI kit.
- Responses pass through tolerant normalizers (`src/lib/admin/normalize.ts`)
  into canonical DTOs (`src/lib/admin/types.ts`), snake_case-tolerant like the
  portal's `lib/normalize.ts`.
- **Role resource bindings are write-only** in the current contract (only the
  replace `PUT` exists) — the bind drawer starts empty and warns that saving
  replaces all bindings. TODO: preload once a `GET .../roles/{id}/resources`
  landed. Grant `effect` (allow/deny) is persisted and enforced (M6).
- The M6 endpoints (`/admin/apps/{appKey}/custom-rules*`,
  `/admin/audit-logs/summary`) land with the parallel backend work; until then
  their sections show the friendly error card.

## Two-factor authentication (TOTP)

Optional hardening for the primary identity, per `docs/design.md` §12 M4:

- **Login step** — when the identity has 2FA enabled, `POST /auth/login` answers
  `{mfa_required: true, mfa_token}` instead of tokens. The login card switches in
  place to a second step: a 6-digit code field (auto-focus, auto-submits at six
  digits, paste-friendly) that posts `{mfa_token, code}` to
  `POST /auth/login/2fa` and stores the returned token pair like a normal login.
  **Backup codes** (`XXXX-XXXX`) are accepted in the same field; a wrong code
  shakes the input with an inline message, an expired challenge returns to the
  password step with a notice.
- **Enrollment** — `/identity/2fa` walks through: intro → scan (QR code from
  `otpauth_uri`, rendered locally via `qrcode`, plus the raw secret with a copy
  button for manual entry) → confirm a live code → the backup-codes screen
  (plaintext, shown once; copy-all + download `.txt`; "I've saved them"
  checkbox gates the Done button).
- **Management** — the same `/identity/2fa` page shows the enabled state with a
  password-confirmed **Disable 2FA** flow; `/identity` reflects live status
  (chip + Enable/Manage card).
- `GET /me` carries `two_fa_enabled`; authoritative state comes from
  `GET /me/2fa/status` → `{enabled, confirmed}`.

## Social login (Google / Microsoft / Facebook / Apple)

Per `docs/design.md` §12 M5, the four provider buttons on `/login` (2×2 grid:
Google and Microsoft in the secondary style, Apple black, Facebook `#1877F2`)
kick off a **full-page browser navigation** — never a fetch — to

```
GET {API_ORIGIN}/api/v1/auth/social/{provider}/start?redirect=<portal path>&mode=login
```

The API origin (not the portal's same-origin rewrite) is used because the whole
flow hops through the provider and back; the `ah.session` cookie is host-wide,
so the backend can identify the caller on `mode=link` starts. The `redirect`
carries the validated SSO `next` target when it is a same-origin relative path,
otherwise `/workspaces`.

The provider callback lands back on the portal at **`/social/complete`** with
exactly one of:

- `?login_code=<code>` (login success) — the page exchanges it once via
  `POST /auth/social/complete {login_code}`:
  - **token pair** → `applySession` (localStorage + `ah.session` cookie) and
    the usual post-login redirect (honors a `next`/`redirect` param passed
    through the hop); when the response includes
    `pending_invitations: [{app_key, app_name}]` (workspace invites matched by
    the verified provider email), a "You may have pending invitations" strip
    with one link to `/invite` per invitation is shown first and the
    auto-redirect (~1.5s) is **deferred**: it fires only if the strip is never
    touched, and any interaction with the strip cancels it (a Continue button
    navigates immediately).
  - **`{mfa_required: true, mfa_token}`** → the same 2FA second step as
    password login (shared `components/mfa-code-step.tsx`); the code posts to
    `POST /auth/login/2fa`, then session + redirect as above.
- `?linked=1` (link success) — "Account linked" card linking to `/identity`.
- `?error=<reason>` — error card with friendly copy:
  `not_registered` ("…create a Company ID first or ask for an invite"),
  `already_linked`, `invalid_state` (session expired), `account_disabled`,
  `provider_error` (generic); unknown/missing params get a generic
  "This link has expired" card with a back-to-`/login` button.

## Linking and unlinking providers

The **Connected accounts** card on `/identity` lists the social credentials
linked to the Company ID (`GET /me/social-identities`: provider icon, email,
verified chip, linked date):

- **Connect** buttons are rendered for every provider not linked yet
  (`mode=link`, `redirect=/social/complete`). Whether a provider is configured
  is server-side knowledge, so the portal probes the start endpoint through the
  same-origin rewrite first (`fetch` with `redirect: "manual"`) and surfaces a
  missing provider (404) as an error toast instead of a raw backend page;
  success leaves the portal for the provider's consent screen.
- **Unlink** is a two-step confirm (Unlink → Confirm unlink / Cancel) calling
  `DELETE /me/social-identities/{id}`. A **409** — unlinking the last
  remaining sign-in method — is rejected and the backend's message is shown as
  an error toast.
- `GET /me/signin-methods` includes the social entries; the workspace detail
  page's sign-in methods card renders them with the provider brand marks.

## SSO `next` contract

The backend's OIDC browser flow (`GET /oauth2/authorize`) 302s anonymous users
into the portal at `/login?next=<target>`:

- Relative targets (`/foo`) are honored when they start with a single `/`
  (no `//` or `/\` protocol-relative tricks).
- Absolute `http(s)` targets are honored **only** when their origin matches the
  API origin (`ACCESS_HUB_API_URL`, inlined as
  `NEXT_PUBLIC_ACCESS_HUB_API_URL` by `next.config.ts`) — the usual case is the
  hop back to `/oauth2/authorize` on the API origin, which needs a full browser
  navigation.
- Anything else (off-site URLs, other schemes, empty) is ignored and the user
  lands on `/workspaces`.

After a successful login (including the 2FA step, password or social),
registration, and invite auto-login, the portal also writes a lightweight
**`ah.session` cookie**
(`value = access token`, `SameSite=Lax`, `Path=/`, non-HttpOnly — JS cannot set
HttpOnly, so it carries no privilege beyond what localStorage already holds)
whose `Max-Age` mirrors the access token's `exp` claim. The backend browser flow
reads this cookie to resume `GET /oauth2/authorize`. Helpers live in
`src/lib/session.ts` (`applySession` / `endSession` /
`setSessionCookie` / `clearSessionCookie`); they run on login, logout, silent
refresh rotation, and session expiry.

## Auth & tokens

- Portal tokens in `localStorage`: `ah.access` / `ah.refresh`; plus the
  `ah.session` cookie for backend browser flows (see above).
- Workspace app tokens stored separately per account: `ah.app.{accountId}.access`
  (and `.refresh`).
- The global fetch wrapper (`src/lib/api.ts`) attaches `Authorization: Bearer`,
  and on a 401 tries **one** silent `POST /auth/token/refresh` (rotating the stored
  pair and re-stamping the cookie) before retrying; a failed refresh clears the
  session and returns to `/login`.
- `GET /me` drives the header avatar and the persistent
  **"Please change your password"** banner (`must_change_password`) that links to
  `/me/password`. The banner keeps working across the 2FA login step — it is
  rendered from the same `GET /me` after tokens land.
- Errors use the `{service, code, message, error}` envelope
  (1400/1401/1403/1404/1409/1500) and are mapped to friendly inline/toast messages.

## Notes

- Dev mail driver: password-reset codes are printed to the **backend server log**;
  the forgot-password page shows a dismissible hint about it.
- Social login runs entirely through the backend's `start` → provider →
  callback redirect chain (see "Social login" above); OIDC client management
  screens are admin-side and out of scope for the portal.
- Workspace accounts are **linked automatically** when you accept an invite;
  social accounts are linked/unlinked explicitly from `/identity` (v6 design).
