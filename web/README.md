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
| `/login` | Company ID sign-in, 2FA step, SSO `next` redirect (+ disabled Google/Microsoft) | `POST /auth/login`, `POST /auth/login/2fa` |
| `/register` | Create Company ID, auto-login | `POST /auth/register` |
| `/forgot-password` | email → code → new password | `POST /auth/email/code`, `POST /auth/password/reset` |
| `/workspaces` | workspace picker ("Welcome back") | `GET /me/workspaces`, `POST /me/workspaces/{accountId}/token` |
| `/identity` | primary identity + 2FA status + linked accounts | `GET /me`, `GET /me/2fa/status`, `GET /me/workspaces` |
| `/identity/2fa` | TOTP enrollment wizard / 2FA management | `GET /me/2fa/status`, `POST /me/2fa/enroll`, `POST /me/2fa/confirm`, `POST /me/2fa/disable` |
| `/workspace/[accountId]` | workspace detail (access & role, sign-in methods) | `GET /me/workspaces/{accountId}`, `GET /me/signin-methods` |
| `/invite` | redeem invitation (works signed-in or anonymous) | `POST /invitations/redeem`, `POST /invitations/accept` |
| `/me/password` | change password | `PATCH /me` |

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

After a successful login (including the 2FA step), registration, and
invite auto-login, the portal also writes a lightweight **`ah.session` cookie**
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
- Google/Microsoft social login is still a disabled placeholder (M5 per
  `docs/design.md` §12). OIDC client management screens are admin-side and out of
  scope for the portal.
- Workspace accounts are **linked automatically** when you accept an invite;
  there is no manual link/unlink flow (v6 design).
