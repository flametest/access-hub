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
| `/login` | Company ID sign-in (+ disabled Google/Microsoft) | `POST /auth/login` |
| `/register` | Create Company ID, auto-login | `POST /auth/register` |
| `/forgot-password` | email → code → new password | `POST /auth/email/code`, `POST /auth/password/reset` |
| `/workspaces` | workspace picker ("Welcome back") | `GET /me/workspaces`, `POST /me/workspaces/{accountId}/token` |
| `/identity` | primary identity + linked accounts | `GET /me`, `GET /me/workspaces` |
| `/workspace/[accountId]` | workspace detail (access & role, sign-in methods) | `GET /me/workspaces/{accountId}`, `GET /me/signin-methods` |
| `/invite` | redeem invitation (works signed-in or anonymous) | `POST /invitations/redeem`, `POST /invitations/accept` |
| `/me/password` | change password | `PATCH /me` |

## Auth & tokens

- Portal tokens in `localStorage`: `ah.access` / `ah.refresh`.
- Workspace app tokens stored separately per account: `ah.app.{accountId}.access`
  (and `.refresh`).
- The global fetch wrapper (`src/lib/api.ts`) attaches `Authorization: Bearer`,
  and on a 401 tries **one** silent `POST /auth/token/refresh` (rotating the stored
  pair) before retrying; a failed refresh clears the session and returns to
  `/login`.
- `GET /me` drives the header avatar and the persistent
  **"Please change your password"** banner (`must_change_password`) that links to
  `/me/password`.
- Errors use the `{service, code, message, error}` envelope
  (1400/1401/1403/1404/1409/1500) and are mapped to friendly inline/toast messages.

## Notes

- Dev mail driver: password-reset codes are printed to the **backend server log**;
  the forgot-password page shows a dismissible hint about it.
- 2FA ("Secured with 2-factor authentication" footer, 2FA chip) is rendered as a
  placeholder — enrollment lands in M4 per `docs/design.md` §12. Same for
  Google/Microsoft social login (M5).
- Workspace accounts are **linked automatically** when you accept an invite;
  there is no manual link/unlink flow (v6 design).
