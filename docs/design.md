# Access-Hub 设计方案

通用用户中心 + 多应用权限管理系统（IAM），**多租户（org）+ 主账号/子账号两层身份**。

> **状态：v6（M1–M5 已实现，M6 待实施）**
> M4 实施落点（2026-09-01）：`migration/0002_m4.sql`（oauth_clients / oauth_refresh_tokens / totp_secrets，accounts.password_hash 放开可空）；go-oauth2/v4 引擎 + 自建 OIDC 层（discovery/id_token RS256 含 nonce+at_hash/userinfo）；TOTP 可选增强（enroll→confirm→backup codes，登录挑战 `/auth/login/2fa`，mfa_token 短时 JWT）；service client 默认自有 app 全量策略（loader `p, client:{id}, app:{key}, *, *`，**创建/启停即触发策略 reload**）；前端登录 2FA 步骤 + `/identity/2fa` 向导 + SSO `next` 重定向与 `ah.session` cookie 契约。
> 实施落点（2026-08-30）：后端 M1–M3 全部落地并通过全量测试（含一条 sqlite httptest 全链路集成测试）与真机冒烟（docker pg/redis + `scripts/smoke.sh`）；门户前端 `web/` 按 §9 映射实现（Next.js 16 + React 19 + Tailwind 4，构建通过）。实施期补充的契约细节：① `PATCH /me` 改密需 `current_password` 验证 ② `POST /invitations/accept` 在自动创建主账号时返回 tokens 供前端自动登录 ③ admin 资源码税表：平台码 `admin:org:* / admin:user:* / admin:audit:*` 仅 super_admin，其余（`admin:app:* / admin:account:* / admin:invitation:* / admin:resource:* / admin:role:* / admin:grant:*`）org_admin 自动绑定 ④ dev 环境宿主机 5432 被占用，compose 将 PG 映射到 **5433**（server-config.yaml 已对应）。
> v6 修订要点（用户决策）：**子账号保留独立密码，主账号缺位时自动创建**：① 恢复子账号独立登录凭证与 `/auth/account-login` 直登 ② 绑定约束不变——子账号创建（邀请接受/管理员指派）时无主账号则**自动创建主账号**并绑定 ③ 邀请接受无需预注册：当场所设密码同时初始化主账号与子账号（出生同值，此后独立）；管理员指派则双方各凭邮件激活设密 ④ 关联（link/unlink）流程废弃，交接走管理员 transfer。
> v6 补充：密码存储采用 **bcrypt 内建加盐**——每密码随机 128-bit 盐已内嵌于哈希串，**拒绝手动 `password+salt` 预拼接**（冗余且触发 bcrypt 72 字节截断风险），见 §7；可选 pepper 增强。
> v5 存档：子账号强制挂主账号（绑定约束沿用；"登录凭证统一在主账号"已被 v6 推翻）。
> v4 存档：身份两层拆分（users 主账号 / accounts 子账号）、Casbin 主体改为 account、成员资格门禁被结构性取代、门户工作台换发 app token、邀请流程、前端原型映射（§9）。
> v3 修订存档：多租户模型、Casbin 多实例 Watcher 同步、token 双 aud、全局角色 roles.scope、email 码 Redis 单存储、obj 精确匹配（无通配资源）、partial unique index、refresh 原地轮换、登出吊销 session、授权关系 expires_at/granted_by/effect、防爆破与密码策略、批量资源导入、admin 资源代码内声明、fail-close。

## 1. 定位

自建 IdP + 集中式授权中心（PDP），多租户，主/子两层账号：

- **主账号（Company ID / identity）**：一个人的全局身份，持有登录凭证（密码、社交、2FA），一次登录通达其名下所有 workspace
- **子账号（workspace account）**：各 app 的登录账号（app 内邮箱/用户名 + **独立密码**，可直登），**必须挂在一个主账号下**——无主账号时自动创建；角色与权限挂在子账号上
- **多租户**：org 是租户容器，app 归属 org；平台运营方（super_admin）与租户自治（org_admin）两级管理
- **授权（PDP）**：资源统一建模（菜单/API/按钮），角色授权 + 子账号直接授权 + 超管三层

## 2. 核心设计决策

### 2.1 身份两层：主账号（identity）与子账号（account）

- **users = 主账号**：全局唯一身份，持有门户凭证（password、邮箱验证码、社交 M5、TOTP M4）与 profile；本身不直接持有业务 app 权限；`password_hash` 可空——自动创建且尚未设密的主账号不能登录门户，须先经邮箱设密
- **accounts = 子账号**：`(app_id, email)` 唯一的 per-app 登录账号，持有**独立密码**、角色（account_roles）与直接授权；**`identity_id` 非空——绑定唯一主账号，创建时若无主账号则自动创建**（用户决策）；**子账号邮箱 ≠ 主账号邮箱是常态**（已确认：app 内工作邮箱 vs 个人主邮箱）——自动创建主账号时以邀请/指派邮箱为主账号邮箱；绑定与登录互不影响：直登只认子账号邮箱+密码，门户只认主账号凭证
- **两条创建路径**：① 邀请接受——redeem 邀请码即创建子账号；被邀人未登录时按邀请邮箱自动创建主账号，当场所设密码**同时初始化**主账号与子账号（出生同值，此后各自独立）② 管理员指派——按邮箱开通子账号（其邮箱无主账号则自动创建、暂无密码），双方各凭激活邮件设密。不支持无邀请自助加入
- **两种登录入口**：① 子账号直登——`{app, email/username, password}` → 该 app token（业务 app 登录页，日常主路径）② 主账号登录——`{identifier, password}` → 中心 token → 工作台选择器 → 换发目标 workspace 的 app token（门户路径）。业务 app 内的登录主体始终是子账号（token sub=account_id）
- **一个主账号可持有多个子账号**（含同 app 的不同 persona，如个人/工作）；**换主账号**（员工离职交接）是管理员操作（transfer），不做自助关联/解绑
- **原"成员资格门禁"被结构性取代**：Casbin 主体就是子账号，子账号结构上属于唯一 app + 唯一主账号，天然隔离

### 2.2 多租户：身份全局、授权按 (org, app) 隔离

- org 是租户容器：`orgs` + `org_members`（**仅治理用途**：owner/admin 决定谁能管理本 org 的 app 与元数据）
- app 归属 org（`apps.org_id`，NULL = 平台 app 如 admin 控制台）
- "用户是某 org 的成员" = 拥有该 org 下某 app 的 active 子账号（派生查询，不单独维护业务成员表）
- 两层管理权限：Casbin 管 API 级（admin 域资源码），`org_members.org_role` 管行级范围（平台 super_admin 全量、org_admin 本 org），行级过滤在 service 层

### 2.3 资源统一建模（单表）

一张 `resources` 表，`type` 区分 `menu` / `api` / `button`（可扩展），权限码即资源 code；**不支持通配资源**（已决策）：code 精确标识（如 `order:read`），整组授权靠枚举/前端多选。

### 2.4 Casbin 只做内存求值，不落 casbin_rule 表

- **业务表（account_roles / role_resources / account_grants）是唯一事实来源**；自实现只读 Adapter，启动全量翻译装入 enforcer
- **多实例同步**：写路径 = 本实例事务写业务表 + enforcer 增量更新 → Redis Pub/Sub（`casbin:reload`）广播 → 其余实例全量 reload；`policy:ver:{appKey}` 版本号做下游缓存失效与定时对账兜底

### 2.5 token 双 aud 语义

| token 类型 | aud | 获取方式 | 用途 |
|---|---|---|---|
| **app token** | `{appKey}` | 子账号直登；或中心 token 换发（`POST /me/workspaces/{id}/token`） | 业务 app 本地 RS256 验签（JWKS）；claims 含 `sub=account_id`、`iid=identity_id`、`aid=account_id` |
| **中心 token** | `access-hub` | 主账号登录（不指定 app） | `/me/*`、`/authz/check`、admin API；跨 app 查询菜单/权限 |

## 3. 技术栈（沿用 taskd 约定）

- **Go 1.25 + Echo v4，经 `flametest/vita`**：vserver / verrors / vgorm / vredis / viper / zerolog / validator
- **新增依赖**：`casbin/casbin/v2`（自写 loader + redis watcher）、`golang-jwt/jwt/v5`（RS256）、`golang.org/x/crypto/bcrypt`
- **基础设施**：PostgreSQL + Redis；docker-compose（pg / redis / mailhog，开发期邮件 console driver）

## 4. 工程结构（镜像 taskd 布局）

```
access-hub/
├── cmd/access-hub/main.go          # config → container → vserver → Router
├── cmd/migrate/main.go             # 顺序执行 migration/*.sql，记录 schema_migrations
├── internal/
│   ├── api/router.go
│   ├── api/middleware/             # JWT 认证、org 行级范围
│   ├── api/handler/                # 每端点一文件 + converter/；admin 资源清单代码内声明
│   ├── config/config.go            # viper yaml + fail-fast 校验
│   ├── container/container.go
│   ├── domain/                     # user/account/org/app/resource/role… 实体行为
│   ├── service/                    # auth/identity/account/workspace/link/invite/org/app/resource/role
│   ├── infra/model/                # gorm 模型
│   ├── infra/repository/
│   ├── infra/jwt/                  # RS256 密钥加载、签发、验签、JWKS
│   ├── infra/casbin/               # enforcer、模型文本、loader、redis watcher
│   ├── infra/mailer/               # console(开发)/smtp
│   └── constant/enum/
├── pkg/dto/
├── migration/                      # init.sql + seed.sql
├── deploy/server-config.yaml
├── docker-compose.yml / Dockerfile / Makefile / docs/design.md
```

## 5. 数据模型（M1–M3）

**通用约定**：唯一约束一律 **partial unique index（WHERE deleted_at IS NULL）**；username/email 存储/查找/唯一均 **lower() 归一**；授权关系统一 `granted_by/granted_at/expires_at`（NULL=永久）；`effect` 列预留（M1–M3 恒 allow）。

| 表 | 字段要点 |
|---|---|
| **users**（主账号） | username(全局唯一)、email(全局唯一)、email_verified、password_hash(**可空**——自动创建未设密)、nickname、avatar_url、status(active/disabled)、must_change_password、last_login_at |
| **accounts**（子账号） | **identity_id 非空（绑定主账号，无则自动创建）**、(app_id, email) 唯一；username 可空（(app_id, username) 唯一）；**password_hash 非空（独立登录凭证，激活时设置）**；display_name；status(pending_activation/active/disabled)；source(invite/provisioned)；last_login_at。（无独立关联表：绑定即 `accounts.identity_id`；换绑为管理员 transfer 操作） |
| **invitations**（邀请） | app_id、email、role_ids jsonb、invited_by(admin 的 account_id)、code_hash、expires_at、accepted_at/account_id、status(pending/accepted/revoked/expired) |
| **orgs** | key(唯一)、name、status |
| **org_members**（治理） | (org_id, user_id) 唯一；org_role：owner/admin（仅 org 治理，非业务成员） |
| **apps** | key(唯一)、org_id(可空=平台 app)、name、type(web/native/service)、description、logo_url、status |
| **resources** | app_id、parent_id、type(menu/api/button)、code((app_id,code) 唯一)、name、sort、status、visible、icon、method+route_path(api 用，部分唯一索引)、extra jsonb |
| **roles** | (app_id, code) 唯一、name、scope(app/global)、built_in；global 内置：super_admin、org_admin |
| **role_resources** | (role_id, resource_id) 唯一；effect 预留 |
| **account_roles** | (account_id, role_id) 唯一；granted_by/at、expires_at |
| **account_grants**（直接授权） | (account_id, resource_id) 唯一；granted_by/at、expires_at、effect 预留 |
| **sessions** | user_id、scope(identity/account)、account_id 可空、app_id(登录入口)、refresh_token_hash(唯一)、device、ip、last_used_at、rotation_count、expires_at、revoked_at —— 原地轮换 |
| **audit_logs** | actor(user/account)、org_id、action、target_type/id、detail jsonb、ip、user_agent、created_at |

**仅 Redis**：邮箱验证码（`email:code:*` hash+TTL+错误计数）、发送/登录限频与锁定（`rl:*`、`login:*`）、`jwt:deny:{jti}`、`policy:ver:{appKey}`、`casbin:reload`。
**预留**：identities（社交凭证，M5）、oauth_clients（M4）、custom_rules（M6）、totp_secrets（M4）。

## 6. Casbin 模型与鉴权集成

```ini
[request_definition]  r = sub, dom, obj, act
[policy_definition]   p = sub, dom, obj, act
[role_definition]     g = _, _, _
[policy_effect]       e = some(where (p.eft == allow))
[matchers]            m = (r.sub == p.sub || g(r.sub, p.sub, r.dom) || g(r.sub, p.sub, "*"))
                          && (r.dom == p.dom || p.dom == "*")
                          && r.obj == p.obj
                          && (r.act == p.act || p.act == "*")
```

- **sub = `account:{id}`**（子账号是 per-app 主体，结构性归属唯一 app）
- obj 精确匹配（无通配资源）；act 允许策略侧 `*`；dom 的 `*` 仅供超管 seed

### 6.1 业务表 → 策略规则（只读 loader）

| 业务表 | 翻译为 |
|---|---|
| role_resources（scope=app） | `p, role:{code}, app:{key}, {resource.code}, *` |
| role_resources（scope=global） | `p, role:{code}, app:{资源所属app}, {resource.code}, *`（dom 跟资源走，org_admin 不越权业务 app） |
| account_roles（scope=app 角色） | `g, account:{id}, role:{code}, app:{key}` |
| account_roles（scope=global） | `g, account:{id}, role:{code}, *` |
| account_grants | `p, account:{id}, app:{资源app}, {resource.code}, *` |
| seed（超管） | `p, role:super_admin, *, *, *` |

**super_admin / org_admin 授予"admin 平台 app 里的子账号"**（管理动作都在 admin 域），不跨 app 授予。

**三条运行路径**：

```
启动:    PG 业务表 ──loader 全量翻译──▶ 本实例 enforcer（无条件全量）
运行:    请求(token→account_id) ─▶ enforcer.Enforce(account:{id}, app:{key}, obj, act)  ← 纯内存
变更:    事务写业务表 ─▶ 本实例增量同步 ─▶ 版本号自增 ─▶ PUBLISH casbin:reload
              └─▶ 其余实例全量 reload；定时版本号对账兜底
```

**规模说明**：g 链接量 ≈ 子账号数 × 角色数，适合 B 端 ~50 万账号内；更大规模走 `/me/permissions` 预计算权限集 + 版本号本地缓存。

### 6.2 业务 app 接入方式

1. **本地验 JWT**：app token（aud=appKey，sub=account_id），公钥 `GET /.well-known/jwks.json`；业务系统以 account_id 为其用户主键
2. **细粒度鉴权**：`POST /api/v1/authz/check {app, obj(code) | method+path, act}`（中心 token 或对应 app token）→ Casbin enforce，结论按 `policy:ver` 缓存；PDP 不可用默认 **fail-close**；建议接入方缓存 `/me/permissions` 快照降级
3. **前端菜单/按钮**：`GET /api/v1/me/menus?app=`（menu 资源树按权限过滤）、`GET /api/v1/me/permissions?app=`（权限码集合+版本号）

**admin 控制台吃狗粮**：admin 是平台 app；平台管理员 = admin app 的子账号（bootstrap 邀请创建）；资源清单代码内常量声明、启动自动同步；super_admin 全量，org_admin 绑定 admin 资源子集 + org_members 行级圈定。

## 7. 认证设计

- **access token**：RS256 JWT 15min，claims: iss/sub(account 或 user)/aud(双轨)/exp/jti/sid/iid/aid
- **refresh token**：256bit opaque，sha256 落库，**原地轮换**（同 session 行更新 hash、rotation_count++）；旧 hash 重现 → 判泄露吊销整条 session
- **登出**：吊销 session + jti 入 Redis denylist；主账号改密/重置密 → 吊销其全部 identity-scope session（工作台换发的 app session 属于子账号，随 refresh 过期，可另行强制吊销）；子账号密码重置 → 吊销该子账号全部 session
- **主账号登录**：`{identifier(email/username), password}` + bcrypt（未设密的自动主账号拒绝登录并提示走邮箱设密）；**防爆破**：5 次失败锁 15 分钟（账号+IP 双维度）；预留验证码挂钩
- **子账号直登**：`{app, email/username, password}` → app token；同套防爆破（键含 app）
- **邮箱验证码**：仅 Redis（6 位、TTL 10min、错 5 次作废、发送限频 60s/邮箱 + 10 次/时/IP）；未注册邮箱按开关自动注册主账号（默认关）
- **主账号自动创建（auto-provision）**：子账号创建时其邮箱无主账号 → 自动创建（email_verified=true，邀请码/指派邮件已验证邮箱）。凭证初始化：邀请接受路径，用户当场所设密码**同时写入**主账号与子账号（此后独立演化）；管理员指派路径，双方均无密码，各收一封"设置密码"邮件（`/auth/password/set`、`/auth/accounts/activate`）。无独立 link/unlink 流程——绑定在创建时自动发生
- **邀请（invite）**：org_admin 在 admin 端创建（app、email、角色集、有效期，邮件发 code/链接）→ 被邀人 `POST /invitations/redeem {code}`——**无需预注册**：已登录则绑定当前主账号；未登录则按邀请邮箱自动创建主账号并当场设密 → 确认信息（workspace、角色、邀请人，凭有效 code 才返回，不泄露）→ accept：创建 active 子账号（绑定主账号）+ account_roles
- **密码存储（bcrypt 内建加盐，已覆盖"加盐哈希"诉求）**：bcrypt 每次哈希自动生成 **128-bit 加密安全随机盐**并内嵌于输出串——格式 `$2b$<cost>$<22字符盐><31字符哈希>`，"哈希+盐"一体存储，验证用 `bcrypt.CompareHashAndPassword`（恒时比较）。**不做手动 `password + salt` 预拼接**：① bcrypt 输入上限 72 字节，外部盐（Base64 后 24 字符）会挤占预算、超出部分被**静默截断**，长密码等效碰撞是真实漏洞 ② 与内建盐重复，无任何安全增益。手动"存哈希+存盐"两列模式属于 PBKDF2/HMAC 类方案，bcrypt 不适用
- **密码策略**：长度 8–72（上限即 bcrypt 输入上限，超长拒绝、绝不截断）+ 字符集 + 弱口令表；bcrypt cost 默认 12、可配置（测试环境调低加速）；**可选 pepper**：`bcrypt(HMAC-SHA256(server_secret, password))`，密钥存配置/KMS 不落库，防拖库后离线爆破——默认关闭（换 pepper 需全员改密）；username 保留字表；must_change_password（bootstrap/重置后）全接口 403 促改密
- **Bootstrap**：seed 平台 admin app + 资源（代码同步）+ super_admin/org_admin + orgs(演示) + 初始主账号（密码来自环境变量，must_change_password=true）及其在 admin app 的子账号（密码同源初始化）

## 8. API 清单（M1–M3）

- **公开**：`POST /api/v1/auth/register | /auth/login(主账号) | /auth/account-login(子账号直登) | /auth/email/code | /auth/email/login | /auth/token/refresh | /auth/logout | /auth/password/set(主账号邮箱设密) | /auth/accounts/activate(指派子账号设密)`；`GET /.well-known/jwks.json`；`/health` `/ready`
- **登录态（中心 token）**：
  - `GET/PATCH /api/v1/me`（profile/改密，改密全下线）
  - `GET /api/v1/me/workspaces`——工作台列表（关联子账号 + app + org + 角色摘要 + status），门户选择器数据源
  - `POST /api/v1/me/workspaces/{accountId}/token`——换发该 workspace 的 app token（新 session，scope=account）
  - `GET /api/v1/me/menus?app=`、`GET /api/v1/me/permissions?app=`
  - `GET /api/v1/me/signin-methods`（密码/邮箱/社交/2FA，last-method 保护）
  - `GET /api/v1/me/sessions`、`DELETE /api/v1/me/sessions/:id`、`DELETE /api/v1/me/sessions`
- **邀请**：`POST /api/v1/invitations/redeem {code}`（主账号登录态）
- **业务接入**：`POST /api/v1/authz/check`（method+path 反查唯一资源，反查不到即 deny）
- **管理端（Casbin dom=admin + org 行级）**：orgs CRUD + org_members 治理；apps CRUD；users（主账号）列表/禁用/重置密码；**accounts（子账号）列表/禁用/重置密码/设角色/换绑主账号(transfer)**；invitations 创建/列表/撤销；resources 树 CRUD + `PUT .../resources:batch`（幂等导入）；roles CRUD + `PUT /roles/:id/resources`；account_grants 管理；`GET /admin/audit-logs`

## 9. 前端门户映射（login.html 原型 → API）

| 原型屏幕 | 对应端点 |
|---|---|
| Company ID 登录（密码 + Google/Microsoft） | `POST /auth/login`（社交 M5） |
| Welcome back 工作台选择器 | `GET /me/workspaces` |
| Open workspace → "You're in X / Back to workspaces" | `POST /me/workspaces/{id}/token` 后跳转/嵌入业务 app |
| Identity 卡片 + Linked accounts | `GET /me` + `GET /me/workspaces` |
| 子账号详情（Access & role / Sign-in methods） | `GET /me/workspaces/{id}`（含角色）、`GET /me/signin-methods` |
| Enter invite code → Confirm invitation | `POST /invitations/redeem`（两段式：code 校验返回确认信息 → accept；未登录自动创建主账号并设密） |
| Discover with Google/Microsoft | M5 社交登录（主账号侧） |
| Account linked 成功页 | redeem accept 响应 |

原型缺口（前端后续需补）：主账号**注册页**、忘记密码流程页、**2FA 设置页**（页脚已宣称 2FA）、admin 端全部界面（邀请管理、子账号管理）；原型中 "Sign in to an existing account / Unlink" 屏随绑定模型简化废弃（绑定在创建时自动发生），子账号直登发生在各业务 app 自己的登录页（原型未含）。另有两处文案笔误：`Compay ID`→`Company ID`；演示数据 `Altas` 疑为 `Atlas`。

## 10. 非功能与安全策略

- **性能**：authz/check 内存 enforce 微秒级，端到端 P99 < 20ms（含 Redis 缓存）
- **可用性**：PDP 默认 fail-close；Redis 不可用时 denylist 降级 fail-open 需显式配置；接入方建议本地权限快照
- **扩展**：实例无状态，Watcher + 版本号对账收敛，可横向扩容
- **可观测**：/metrics + 策略 reload 次数 / watcher 对账延迟 / 登录失败与锁定 / 发码量
- **安全**：bcrypt 内建盐 + cost 12（详见 §7 密码存储）；TLS 网关终止；audit_logs 保留期可配（默认 180 天）；邀请 code 一次性、短有效期、hash 落库

## 11. 实施顺序（核心闭环 = M1–M3）

- **M1 骨架**：go.mod、config、container、vserver、health/ready、migration/init.sql（v4 全部表 + partial index）+ cmd/migrate、docker-compose、Makefile
- **M2 主账号认证闭环**：JWT（RS256 + make keys）、主账号注册/密码登录/邮箱码、refresh 原地轮换 + 重用检测、登出 denylist、防爆破、密码策略、/me（profile/signin-methods/sessions）、bootstrap、mailer
- **M3 子账号 + 多租户 RBAC**：accounts/invitations/orgs/org_members；子账号直登、**主账号自动创建与激活设密**、工作台列表与 app token 换发、invite 全流程、transfer；apps/resources/roles/account_roles/account_grants 管理 + 批量导入；Casbin（loader + watcher + 对账）；org_admin 行级范围；authz/check + 缓存；me/menus；admin 狗粮；种子数据
- **验证**：单测（service 层 sqlite、Casbin 表驱动）+ httptest 集成测试：注册→主账号登录→工作台→建 org/app/资源/角色→邀请/关联→authz/check→menus 全链路；双 enforcer 实例模拟 watcher 同步

## 12. 后续里程碑

- **M4 OAuth2/OIDC Provider + 2FA（已实现，2026-09-01；真机冒烟 39/39：2FA 全流程、PKCE 授权码交换、id_token nonce/at_hash、userinfo、refresh 轮换+重用吊销、client_credentials 服务身份 + authz/check）**：
  - **选型（已定）**：go-oauth2/v4 做协议引擎（authorize/token/PKCE/client_credentials）+ 自建 OIDC 层（discovery / id_token 复用 jwt.Manager RS256 / userinfo / at_hash、nonce）；zitadel/oidc 因 Storage 接口面过大且需适配其 AuthRequest 状态机而放弃
  - **2FA 策略（已定）**：可选增强。TOTP enroll/confirm/backup codes/disable；开启后 identity（门户）登录多一步挑战（`mfa_required + mfa_token` 短时 JWT 5min → `/auth/login/2fa`）；account 直登不加挑战；backup codes sha256 落库、一次性
  - **账号解析（已定）**：OIDC 首次登录自动开通子账号（password_hash 可空、不可直登、可邮件激活），authorize 亦可显式传 account_id（工作台选择语义）；migration 0002 已放开 accounts.password_hash
  - 端点：`POST /api/v1/oauth/authorize`（SPA JSON 版，center token）+ `GET /oauth2/authorize`（标准重定向版，cookie/bearer，无会话 302 到门户登录）；`POST /oauth2/token`（authorization_code+PKCE / refresh_token 轮换重用吊销 / client_credentials）；`GET /oauth2/userinfo`；`GET /.well-known/openid-configuration`（issuer 来自 auth.issuerURL）；管理端 `/admin/apps/{key}/oauth-clients`（新码 `admin:oauthclient:read|manage`，非平台码→org_admin 自动绑定）；service 客户端默认自有 app 全量策略（loader: `p, client:{key}, app:{key}, *, *`），可后续收紧
- **M5 社交登录（已实现，2026-09-01；identities 表 + 四 provider（google/microsoft/facebook 经 x/oauth2，apple ES256 client_secret + form_post + JWKS 验证）；一次性 state/login_code；verified email 自动合并 + allowAutoRegister 自动注册；mode=link 绑定 + 最后登录方式守卫；/auth/social/complete 尊重 2FA 挑战 + pending_invitations 提示；门户四家按钮 + /social/complete + 关联账户管理卡；接入指南 docs/social-login-setup.md。实施决策：实施决策：① provider 凭证走 server-config.yaml 全局配置（org 级自带凭证后置）② 回调成功后签发一次性 login_code（kv，5min）→ 门户 `POST /auth/social/complete` 换取正式 tokens，token 不进 URL ③ 门户提供全部四家按钮；社交登录遵守 2FA 挑战 ④ verified email 自动合并维持既定决策）：**Google/Microsoft/Facebook（x/oauth2）、Apple（ES256 + form_post）；identities 表；verified email 自动合并；社交登录后按邮箱匹配待接受邀请/同名子账号的提示流程（对应原型 Discover 屏的落地形态）；org 邀请链接直达
- **M6 自定义规则**：custom_rules（expr-lang ABAC）挂 matcher；effect=deny + priority；审计报表 + 管理后台 UI（React+AntD，工作台选择器按 §9 映射）
