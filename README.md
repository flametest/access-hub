# access-hub

通用用户中心 + 多应用权限管理系统（IAM）：主账号（Company ID）+ 子账号（workspace account）两层身份、多租户（org）、资源统一建模（menu/api/button）、Casbin 集中鉴权（PDP）。

> 设计文档（唯一事实来源）：[docs/design.md](docs/design.md)。当前状态：**M1–M3 核心闭环已实现**（认证 + 多租户 RBAC + 门户前端）；OAuth2/OIDC Provider（M4）、社交登录（M5）、自定义规则 ABAC（M6）待实施。

## 架构速览

- **身份两层**：`users`（主账号，持门户凭证）→ `accounts`（子账号，per-app 登录账号，独立密码，持角色/授权，强制绑定主账号，缺位自动创建）
- **授权三层**：角色授权（account_roles → role_resources）、用户直接授权（account_grants）、内置 super_admin 通配
- **Casbin 只做内存求值**：业务表是唯一事实来源，自实现只读 loader 装载策略；多实例经 Redis pub/sub（`casbin:reload`）广播重载，`policy:ver:{app}` 版本号做下游缓存失效
- **双轨 token**：identity token（aud=access-hub，门户/管理）与 account token（aud=appKey，业务 app 本地 RS256 验签，公钥 `GET /.well-known/jwks.json`）

技术栈：Go 1.25 + Echo v4（[vita](https://github.com/flametest/vita) 框架）、PostgreSQL + GORM（vgorm）、Redis（vredis + 自研 kv）、Casbin v2、golang-jwt（RS256）、Next.js 16 + React 19 + Tailwind 4 门户（web/）。

## 快速开始

```bash
# 1. 依赖容器（postgres:5433 / redis:6379 / mailhog:8025）
make compose-up

# 2. RS256 密钥（JWT 签发）
make keys

# 3. 建表 + 种子（admin app、super_admin/org_admin 角色、演示 org/app）
make migrate

# 4. 启动服务（bootstrap 管理员密码必填）
ACCESS_HUB_BOOTSTRAP_ADMIN_PASSWORD='Admin#Passw0rd' make run
# → :8080  /health /ready /.well-known/jwks.json /metrics

# 5. 门户前端
cd web && bun install && bun run dev   # → :3000，API 代理到 :8080
```

端到端冒烟（服务运行中）：`make smoke`（`SMOKE_ADMIN_PASSWORD` 可覆盖管理员密码）。

## 管理入口

bootstrap 管理员：`admin` / `ACCESS_HUB_BOOTSTRAP_ADMIN_PASSWORD`（首登强制改密）。admin API 的资源清单以常量表声明在 `internal/api/admin_resources.go`，启动时自动同步进 resources 表（吃狗粮：admin API 自身走同一套 Casbin 域检查）；org_admin 自动绑定全部 app 域资源码（平台码 `admin:org:* / admin:user:* / admin:audit:*` 仅 super_admin）。

## 常用命令

| 命令 | 说明 |
|---|---|
| `make build` | 编译 server + migrate 到 bin/ |
| `make run` / `make migrate` | 启动服务 / 执行迁移（按文件名幂等） |
| `make test` | Go 全量测试（sqlite 内存库，无需真实 PG/Redis） |
| `make lint` / `make fmt` | golangci-lint / go fmt |
| `make compose-up` / `compose-down` | 开发容器栈 |

## 工程结构

```
cmd/access-hub/        服务入口（config → container → vserver → router → bootstrap）
cmd/migrate/           SQL 迁移工具（schema_migrations 记账）
internal/config        viper YAML 配置 + fail-fast 校验
internal/domain        实体与业务规则（枚举、状态机）
internal/service       认证/工作台/邀请/RBAC/authz/admin 服务层
internal/api           路由、handler（每端点一文件）、中间件、admin 资源常量
internal/infra         model/repository（vgorm）、jwt、casbin（loader+watcher）、kv、mailer、password
pkg/dto                请求/响应 DTO（snake_case + validate）
migration/             init.sql + seed.sql
web/                   门户前端（Company ID 登录 → 工作台 → 身份管理 → 邀请兑换）
docs/design.md         设计方案 v6（讨论与修订史）
```

## 业务 app 接入（三种方式）

1. **本地验 JWT**：业务后端用 JWKS 公钥验 account token（sub=account_id，aud=appKey），以 account_id 作为业务侧用户主键
2. **集中鉴权**：`POST /api/v1/authz/check` `{obj: "order:read"}` 或 `{method: "GET", path: "/orders"}` → `{allowed, version}`（Redis 缓存 60s，策略变更版本号自增自动失效；PDP 故障默认 fail-close）
3. **前端菜单/按钮**：`GET /api/v1/me/menus?app=key`（按权限过滤的菜单树）与 `GET /api/v1/me/permissions?app=key`（权限码集合 + 版本号，可本地缓存）

## 开发约定

沿用 taskd：vita（vserver/verrors/vgorm/vredis）、每端点一 handler 文件、exported interface + unexported impl、`vgorm.BasePostgres`（UUID PK/乐观锁/软删，唯一索引一律 partial `WHERE deleted_at IS NULL`）、错误经 verrors（1400/1401/1403/1404/1409/1500）由 ErrorHandleMiddleware 渲染信封、日志走 `log "…/vlog"`。Go 代码英文注释，设计文档中文。
