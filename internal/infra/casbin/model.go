// Package casbinx wires the access-hub authorization engine: a read-only
// adapter that translates the business tables (role_resources /
// account_roles / account_grants) into Casbin policies per design.md §6.1,
// a Redis pub/sub watcher for multi-instance reloads and the Enforcer
// wrapper used by services.
package casbinx

// ModelText is the Casbin model (design.md §6). dom "*" is reserved for the
// super_admin seed; act "*" is wildcard on the policy side; obj matches
// exactly (no wildcard resources) except for the super_admin seed rule
// `p, role:super_admin, *, *, *`, whose obj "*" must therefore match too.
const ModelText = `[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = (r.sub == p.sub || g(r.sub, p.sub, r.dom) || g(r.sub, p.sub, "*")) && (r.dom == p.dom || p.dom == "*") && (r.obj == p.obj || p.obj == "*") && (r.act == p.act || p.act == "*")
`
