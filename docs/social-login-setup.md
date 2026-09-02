# Social Login Setup (M5)

Per-provider console configuration for access-hub social login. Callback URLs all follow:

```
{Auth.IssuerURL}/api/v1/auth/social/{provider}/callback
# e.g. https://id.example.com/api/v1/auth/social/google/callback
```

Apple uses the same URL but receives a `POST` (form_post). A provider is **enabled** in the runtime only when its credentials below are non-empty; unconfigured providers return 404 on `/start`.

Config lives in `deploy/server-config.yaml` under `Social:` — per-organization provider credentials are a future milestone.

## Google

1. Google Cloud Console → APIs & Services → Credentials → **Create OAuth client ID** (Web application)
2. Authorized redirect URI: `{IssuerURL}/api/v1/auth/social/google/callback`
3. Copy client id/secret into `Social.google.clientId` / `clientSecret`
4. Scopes used: `openid email profile` (profile via `openidconnect.googleapis.com/v1/userinfo`)

## Microsoft

1. Azure Portal → Microsoft Entra ID → App registrations → **New registration** ("Accounts in any organizational directory and personal Microsoft accounts" for `common`)
2. Redirect URI (Web): `{IssuerURL}/api/v1/auth/social/microsoft/callback`
3. Certificates & secrets → create a client secret
4. `Social.microsoft.clientId` / `clientSecret` / `tenant` (`common` default; pin to an org tenant for B2B)
5. Scopes: `openid email profile` (profile via Microsoft Graph `/oidc/userinfo`)

## Facebook

1. developers.facebook.com → Create App → add **Facebook Login** product
2. Valid OAuth Redirect URIs: `{IssuerURL}/api/v1/auth/social/facebook/callback`
3. App settings → copy App ID / App secret
4. `Social.facebook.clientId` / `clientSecret`
5. Scopes: `email,public_profile` — the email permission requires App Review for production apps; Facebook emails are treated as verified

## Apple (Sign in with Apple)

1. Apple Developer → Identifiers → register a **Services ID** (e.g. `com.example.portal`) with "Sign In with Apple" enabled; configure the **return URL** `{IssuerURL}/api/v1/auth/social/apple/callback` (domain must be verified via the `apple-developer-domain-association.txt` file)
2. Keys → create a **Sign in with Apple key** (.p8), download it and note the KeyID
3. Copy into config:

```yaml
Social:
  apple:
    servicesId: com.example.portal   # = client_id
    teamId: YOUR_TEAM_ID
    keyId: YOUR_KEY_ID
    privateKeyPath: deploy/keys/apple/AuthKey_XXX.p8
```

4. The client_secret is minted server-side as an ES256 JWT from the .p8 (never stored in config); Apple posts `code` + `id_token` to the callback (form_post), the id_token is verified against Apple's JWKS
5. The user's real email arrives only on **first** authorization; later logins may return a private relay address — both are stored on the `identities` row

## Portal integration

- Login buttons navigate to `GET /api/v1/auth/social/{provider}/start?redirect=/workspaces` (full browser navigation)
- Completion lands on the portal at `/social/complete?login_code=...` → `POST /api/v1/auth/social/complete` exchanges it once for tokens (or the TOTP challenge); failures land with `?error=not_registered|account_disabled|already_linked|invalid_state|provider_error`
- Account linking: `start?mode=link` (identity token) binds the provider identity to the current user; `GET /api/v1/me/social-identities` + `DELETE /api/v1/me/social-identities/{id}` manage bindings (the last remaining sign-in method cannot be removed)
- Verified provider emails **auto-merge** into an existing Company ID; otherwise a new identity is auto-registered when `Auth.allowAutoRegister` is true
