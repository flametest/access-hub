#!/usr/bin/env bash
# End-to-end smoke test against a running access-hub on :8080.
# Usage: scripts/smoke.sh   (BASE overrides the target; server must be up)
set -euo pipefail

BASE="${BASE:-http://localhost:8080}"
PASS=0; FAIL=0
STATUS=""; BODY=""

req() { # method path token body  -> sets STATUS/BODY, prints a line
  local method="$1" path="$2" token="$3" body="$4"
  local args=(-s -w $'\n%{http_code}' -X "$method" "$BASE$path" -H 'Content-Type: application/json')
  [ -n "$token" ] && args+=(-H "Authorization: Bearer $token")
  [ -n "$body" ] && args+=(-d "$body")
  local raw
  raw=$(curl "${args[@]}")
  STATUS="${raw##*$'\n'}"
  BODY="${raw%$'\n'*}"
  if [[ "$STATUS" == 2* ]]; then
    PASS=$((PASS+1)); echo "ok   $method $path -> $STATUS"
  else
    FAIL=$((FAIL+1)); echo "FAIL $method $path -> $STATUS $BODY"
  fi
}

jget() { python3 -c "import json,sys; d=json.loads(sys.argv[1]); print(d$2)" "$1"; }

echo "== health =="
curl -sf "$BASE/health" >/dev/null && { echo "ok   /health"; PASS=$((PASS+1)); } || { echo "FAIL /health"; exit 1; }
curl -sf "$BASE/.well-known/jwks.json" | grep -q RS256 && { echo "ok   jwks"; PASS=$((PASS+1)); } || { echo "FAIL jwks"; exit 1; }

TS=$(date +%s)
echo "== identity register + me =="
req POST /api/v1/auth/register "" "{\"username\":\"smoke$TS\",\"email\":\"smoke$TS@test.dev\",\"password\":\"SmokePass1\",\"nickname\":\"Smoke\"}"
TOKEN=$(jget "$BODY" "['access_token']")
req GET /api/v1/me "$TOKEN" ""
req GET /api/v1/me/workspaces "$TOKEN" ""

echo "== admin: org + app + resources + role (bootstrap admin is super_admin) =="
ADMIN_PW="${SMOKE_ADMIN_PASSWORD:-Admin#Passw0rd}"
req POST /api/v1/auth/login "" "{\"identifier\":\"admin\",\"password\":\"$ADMIN_PW\"}"
ADMIN_TOKEN=$(jget "$BODY" "['access_token']")
req POST /api/v1/admin/orgs "$ADMIN_TOKEN" "{\"key\":\"smoke$TS\",\"name\":\"Smoke Org\"}"
req POST /api/v1/admin/apps "$ADMIN_TOKEN" "{\"key\":\"smoke-app-$TS\",\"org_key\":\"smoke$TS\",\"name\":\"Smoke App\",\"type\":\"web\"}"
req PUT "/api/v1/admin/apps/smoke-app-$TS/resources:batch" "$ADMIN_TOKEN" \
  "{\"items\":[{\"code\":\"order:read\",\"name\":\"Read orders\",\"type\":\"api\",\"method\":\"GET\",\"route_path\":\"/orders\"},{\"code\":\"menu:dashboard\",\"name\":\"Dashboard\",\"type\":\"menu\",\"path\":\"/dashboard\"}]}"
req POST "/api/v1/admin/apps/smoke-app-$TS/roles" "$ADMIN_TOKEN" "{\"code\":\"member\",\"name\":\"Member\"}"
ROLE_ID=$(jget "$BODY" "['id']")
req GET "/api/v1/admin/apps/smoke-app-$TS/resources" "$ADMIN_TOKEN" ""

echo "== summary: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
