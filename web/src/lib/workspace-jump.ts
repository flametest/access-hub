import { api } from "@/lib/api";
import { setAppTokens } from "@/lib/tokens";
import type { Workspace } from "@/lib/types";

/**
 * jumpToWorkspaceApp opens a workspace:
 *  - SSO-ready (active confidential authorization-code client): mints the
 *    authorization code via AuthorizeSPA and navigates the browser to the
 *    app's redirect URI — the app exchanges the code for its own session.
 *    Returns null (the browser is leaving the portal).
 *  - otherwise: mints the app token (stored per account) and returns the
 *    workspace detail route for the caller to route to (developer path).
 *
 * Errors propagate to the caller (toast).
 */
export async function jumpToWorkspaceApp(
  ws: Workspace,
): Promise<string | null> {
  // The admin console is the portal itself (bootstrap.PlatformAdminAppKey):
  // its "app" is the /admin section, reached by internal navigation — the
  // admin pages ride the portal identity token, no app token or OIDC needed.
  if (ws.app_key === "admin") {
    return "/admin";
  }
  if (ws.sso_ready && ws.oauth_client_id && ws.redirect_uri) {
    const redirectTo = await api.authorizeWorkspace(
      ws.account_id,
      ws.oauth_client_id,
      ws.redirect_uri,
    );
    window.location.href = redirectTo;
    return null;
  }
  const tokens = await api.mintWorkspaceToken(ws.account_id);
  // App tokens are stored per account, separate from the portal tokens.
  setAppTokens(ws.account_id, tokens.access_token, tokens.refresh_token);
  return `/workspace/${ws.account_id}`;
}
