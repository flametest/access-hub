import base64, hashlib, hmac, json, secrets, struct, time, urllib.request, urllib.parse, sys

import os
BASE = os.environ.get("BASE", "http://localhost:8080")
PASS, FAIL = [], []

def call(method, path, token=None, body=None, form=None, basic=None, expect=None):
    url = BASE + path
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode(); headers["Content-Type"] = "application/json"
    if form is not None:
        data = urllib.parse.urlencode(form).encode(); headers["Content-Type"] = "application/x-www-form-urlencoded"
    if token: headers["Authorization"] = "Bearer " + token
    if basic: headers["Authorization"] = "Basic " + base64.b64encode(basic.encode()).decode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            status, raw = r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read().decode()
    try: js = json.loads(raw)
    except Exception: js = {"_raw": raw[:200]}
    ok = (expect is None and 200 <= status < 300) or (expect == status)
    (PASS if ok else FAIL).append(f"{method} {path} -> {status} (want {expect})" if not ok else f"{method} {path} -> {status}")
    if not ok: print("   body:", raw[:300])
    return status, js

def totp(secret, offset=0):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    t = struct.pack(">Q", int(time.time()) // 30 + offset)
    h = hmac.new(key, t, hashlib.sha1).digest()
    o = h[19] & 0xF
    return str((struct.unpack(">I", h[o:o+4])[0] & 0x7FFFFFFF) % 10**6).zfill(6)

def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name + ("" if cond else f"  [{detail}]"))
    if not cond: print("   FAIL:", name, detail)

# ---------- 1. admin login (no 2FA yet) ----------
s, d = call("POST", "/api/v1/auth/login", body={"identifier": "admin", "password": os.environ.get("SMOKE_ADMIN_PASSWORD", "Admin#Passw0rd")})
check("admin login", "access_token" in d, str(d)[:200])
admin = d["access_token"]

# ---------- 2. 2FA enroll -> confirm -> challenge ----------
s, d = call("POST", "/api/v1/me/2fa/enroll", admin)
check("2fa enroll", "secret" in d and "otpauth_uri" in d, str(d)[:200])
secret = d.get("secret", "")
s, d = call("POST", "/api/v1/me/2fa/confirm", admin, body={"code": totp(secret)})
codes = d.get("backup_codes", [])
check("2fa confirm + 8 backup codes", len(codes) == 8, str(d)[:200])

s, d = call("POST", "/api/v1/auth/login", body={"identifier": "admin", "password": os.environ.get("SMOKE_ADMIN_PASSWORD", "Admin#Passw0rd")})
check("login challenged", d.get("mfa_required") is True and d.get("mfa_token"), str(d)[:200])
MT = d["mfa_token"]
s, d = call("POST", "/api/v1/auth/login/2fa", body={"mfa_token": MT, "code": "000000"}, expect=403)
check("wrong TOTP rejected", s == 403)
s, d = call("POST", "/api/v1/auth/login/2fa", body={"mfa_token": MT, "code": totp(secret, 1)})
check("2fa login (offset+1 window)", "access_token" in d, str(d)[:200])
admin = d["access_token"]

# ---------- 3. OIDC: app + confidential PKCE client ----------
TS = str(int(time.time()))
call("POST", "/api/v1/admin/orgs", admin, body={"key": f"m4org-{TS}", "name": "M4 Org"})
call("POST", "/api/v1/admin/apps", admin, body={"key": f"m4app-{TS}", "org_key": f"m4org-{TS}", "name": "M4 App", "type": "web"})
s, d = call("POST", f"/api/v1/admin/apps/m4app-{TS}/oauth-clients", admin, body={
    "name": "web", "client_type": "confidential",
    "grant_types": ["authorization_code", "refresh_token"],
    "redirect_uris": ["http://localhost:9090/cb"],
    "scopes": ["openid", "profile", "email", "offline_access"]})
check("client created", "client_id" in d and "client_secret" in d, str(d)[:300])
cid, csec = d.get("client_id"), d.get("client_secret")

verifier = secrets.token_hex(32)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
s, d = call("POST", "/api/v1/oauth/authorize", admin, body={
    "client_id": cid, "redirect_uri": "http://localhost:9090/cb",
    "scope": "openid profile email offline_access", "state": "st-1",
    "code_challenge": challenge, "code_challenge_method": "S256", "nonce": "n-1"})
check("authorize -> redirect_to", s == 200 and "code=" in d.get("redirect_to", ""), str(d)[:300])
q = urllib.parse.parse_qs(urllib.parse.urlparse(d["redirect_to"]).query)
code = q["code"][0]

s, d = call("POST", "/oauth2/token", form={
    "grant_type": "authorization_code", "code": code,
    "redirect_uri": "http://localhost:9090/cb", "code_verifier": verifier,
    "client_id": cid, "client_secret": csec})
check("token exchange", "access_token" in d and "id_token" in d and "refresh_token" in d, str(d)[:300])
at, rt, idt = d.get("access_token"), d.get("refresh_token"), d.get("id_token", "")
payload = json.loads(base64.urlsafe_b64decode(idt.split(".")[1] + "=" * (-len(idt.split(".")[1]) % 8)))
check("id_token claims", payload.get("nonce") == "n-1" and str(payload.get("sub", "")).startswith("account:"), str(payload)[:200])

s, d = call("GET", "/oauth2/userinfo", token=at)
check("userinfo account subject", str(d.get("sub", "")).startswith("account:") and "email" in d, str(d)[:200])

s, d2 = call("POST", "/oauth2/token", form={"grant_type": "refresh_token", "refresh_token": rt, "client_id": cid, "client_secret": csec})
check("refresh rotation", "access_token" in d2 and d2.get("refresh_token") not in (None, rt), str(d2)[:200])
s, d3 = call("POST", "/oauth2/token", form={"grant_type": "refresh_token", "refresh_token": rt, "client_id": cid, "client_secret": csec}, expect=400)
check("reuse of rotated refresh rejected", s in (400, 401), str(d3)[:200])

# ---------- 4. client_credentials service client ----------
s, d = call("POST", f"/api/v1/admin/apps/m4app-{TS}/oauth-clients", admin, body={
    "name": "service", "client_type": "confidential",
    "grant_types": ["client_credentials"], "redirect_uris": [], "scopes": []})
s, d = call("POST", "/oauth2/token", form={"grant_type": "client_credentials", "client_id": d["client_id"], "client_secret": d["client_secret"]})
check("client_credentials token", "access_token" in d and "refresh_token" not in d, str(d)[:200])
ct = d.get("access_token", "")
s, d = call("GET", "/oauth2/userinfo", token=ct)
check("client subject userinfo", str(d.get("sub", "")).startswith("client:"), str(d)[:200])
call("PUT", f"/api/v1/admin/apps/m4app-{TS}/resources:batch", admin,
     body={"items": [{"code": "api:ping", "name": "Ping", "type": "api", "method": "GET", "route_path": "/ping"}]})
s, d = call("POST", "/api/v1/authz/check", token=ct, body={"obj": "api:ping"})
check("service client own-app allow", d.get("allowed") is True, str(d)[:200])

# ---------- 5. disable 2FA (restore admin for future smokes) ----------
s, d = call("POST", "/api/v1/me/2fa/disable", admin, body={"password": "Admin#Passw0rd"})
check("2fa disable", s == 200)
s, d = call("POST", "/api/v1/auth/login", body={"identifier": "admin", "password": os.environ.get("SMOKE_ADMIN_PASSWORD", "Admin#Passw0rd")})
check("login back to normal (no challenge)", "access_token" in d, str(d)[:200])

print(f"\n===== M4 SMOKE: {len(PASS)} passed, {len(FAIL)} failed =====")
for f in FAIL: print(" FAILED:", f)
sys.exit(1 if FAIL else 0)
