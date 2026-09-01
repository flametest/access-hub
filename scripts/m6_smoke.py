import base64, hashlib, hmac, json, secrets, struct, time, urllib.request, urllib.parse, sys

BASE = "http://localhost:8080"
PASS, FAIL = [], []

def call(method, path, token=None, body=None, expect=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method,
        headers={"Content-Type": "application/json", **({"Authorization": "Bearer " + token} if token else {})})
    try:
        with urllib.request.urlopen(req) as r: status, raw = r.status, r.read().decode()
    except urllib.error.HTTPError as e: status, raw = e.code, e.read().decode()
    try: js = json.loads(raw)
    except Exception: js = {}
    ok = (expect is None and 200 <= status < 300) or (expect == status)
    (PASS if ok else FAIL).append(f"{method} {path} -> {status}" if ok else f"{method} {path} -> {status} want {expect} :: {raw[:160]}")
    return status, js

def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name if cond else f"{name} :: {detail}")
    if not cond: print("   FAIL:", name, detail)

TS = str(int(time.time()))
s, d = call("POST", "/api/v1/auth/login", body={"identifier": "admin", "password": "Admin#Passw0rd"})
admin = d["access_token"]

call("POST", "/api/v1/admin/orgs", admin, body={"key": f"m6-{TS}", "name": "M6 Org"})
call("POST", "/api/v1/admin/apps", admin, body={"key": f"m6app-{TS}", "org_key": f"m6-{TS}", "name": "M6 App", "type": "web"})
call("PUT", f"/api/v1/admin/apps/m6app-{TS}/resources:batch", admin, body={"items": [
    {"code": "order:read", "name": "Read", "type": "api", "method": "GET", "route_path": "/orders"},
    {"code": "order:delete", "name": "Del", "type": "api", "method": "DELETE", "route_path": "/orders"},
    {"code": "menu:dashboard", "name": "Dash", "type": "menu", "path": "/dashboard"}]})
s, d = call("POST", f"/api/v1/admin/apps/m6app-{TS}/roles", admin, body={"code": "member", "name": "Member"})
rid = d["id"]
res = call("GET", f"/api/v1/admin/apps/m6app-{TS}/resources", admin)[1]
ids = {}
def walk(n):
    ids[n["code"]] = n["id"]
    for c in n.get("children", []): walk(c)
for n in res: walk(n)
call("PUT", f"/api/v1/admin/apps/m6app-{TS}/roles/{rid}/resources", admin,
     body={"items": [{"resource_id": ids["order:read"]}, {"resource_id": ids["menu:dashboard"]}]})
call("POST", f"/api/v1/admin/apps/m6app-{TS}/accounts", admin,
     body={"email": f"bob-{TS}@m6.dev", "role_ids": [rid], "password": "BobPassw0rd"})
s, d = call("POST", "/api/v1/auth/account-login", body={"app": f"m6app-{TS}", "identifier": f"bob-{TS}@m6.dev", "password": "BobPassw0rd"})
bob = d["access_token"]

s, d = call("POST", "/api/v1/authz/check", bob, body={"obj": "order:read"})
check("baseline allow", d.get("allowed") is True, str(d))
s, d = call("POST", "/api/v1/authz/check", bob, body={"obj": "order:delete"})
check("baseline deny", d.get("allowed") is False, str(d))
s, d = call("GET", f"/api/v1/me/menus?app=m6app-{TS}", bob)
check("menu visible", "menu:dashboard" in json.dumps(d), str(d)[:200])

# role deny on order:read (priority 45 beats role allow... same ladder: deny replaces allow in binding)
call("PUT", f"/api/v1/admin/apps/m6app-{TS}/roles/{rid}/resources", admin,
     body={"items": [{"resource_id": ids["order:read"], "effect": "deny"}, {"resource_id": ids["menu:dashboard"]}]})
s, d = call("POST", "/api/v1/authz/check", bob, body={"obj": "order:read"})
check("role deny flips check", d.get("allowed") is False, str(d))
# restore allow via grant (30 beats role deny 45)
s2, d2 = call("GET", f"/api/v1/admin/apps/m6app-{TS}/accounts", admin)
acct = [a for a in d2.get("items", d2 if isinstance(d2, list) else []) if str(a.get("email","")).startswith("bob-")]
acct_id = acct[0]["id"] if acct else None
call("POST", f"/api/v1/admin/apps/m6app-{TS}/accounts/{acct_id}/grants", admin,
     body={"resource_id": ids["order:read"], "effect": "allow"})
s, d = call("POST", "/api/v1/authz/check", bob, body={"obj": "order:read"})
check("grant allow(30) beats role deny(45)", d.get("allowed") is True, str(d))

# custom rule deny at 40 (between grant 30 and role deny 45? no: 40 < 45; but grant allow=30 still wins)
s, d = call("POST", f"/api/v1/admin/apps/m6app-{TS}/custom-rules", admin,
            body={"name": "block-delete", "expr": 'obj == "order:delete"', "effect": "deny", "priority": 40})
check("custom rule created", s in (200, 201), str(d)[:200])
s, d = call("POST", f"/api/v1/authz/check", bob, body={"obj": "order:delete"})
check("ABAC deny blocks", d.get("allowed") is False, str(d))
s, d = call("POST", f"/api/v1/admin/apps/m6app-{TS}/custom-rules/test", admin,
            body={"expr": 'obj == "order:read"', "obj": "order:read"})
check("dry-run allowed", d.get("allowed") is True, str(d)[:200])
s, d = call("POST", f"/api/v1/admin/apps/m6app-{TS}/custom-rules/test", admin,
            body={"expr": "this is not (( valid", "obj": "x"}, expect=400)
check("invalid expr 400", s == 400, str(d)[:120])
s, d = call("POST", f"/api/v1/admin/apps/m6app-{TS}/custom-rules", admin,
            body={"name": "biz-hours", "expr": "'member' in roles", "effect": "allow", "priority": 40})
s, d = call("POST", "/api/v1/authz/check", bob, body={"obj": "order:read"})
check("roles env allow", d.get("allowed") is True, str(d))

# cleanup rules then confirm summary endpoint
s, d = call("GET", f"/api/v1/admin/apps/m6app-{TS}/custom-rules", admin)
for r in (d if isinstance(d, list) else d.get("items", [])):
    call("DELETE", f"/api/v1/admin/apps/m6app-{TS}/custom-rules/{r['id']}", admin)
s, d = call("GET", "/api/v1/admin/audit-logs/summary?days=7", admin)
check("audit summary shape", isinstance(d.get("by_action"), list) and isinstance(d.get("daily"), list), str(d)[:200])

print(f"\n===== M6 SMOKE: {len(PASS)} passed, {len(FAIL)} failed =====")
for f in FAIL: print(" FAILED:", f)
sys.exit(1 if FAIL else 0)
