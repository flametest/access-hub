// Package casbinx wires the access-hub authorization engine: a read-only
// adapter that translates the business tables (role_resources /
// account_roles / account_grants / custom_rules) into Casbin policies per
// design.md §6.1/§12-M6, a Redis pub/sub watcher for multi-instance reloads
// and the Enforcer wrapper used by services.
package casbinx

// ModelText is the Casbin model (design.md §6, M6 revision). It is a 7-tuple
// model with explicit priority + effect + ABAC condition:
//
//		p = priority, sub, dom, obj, act, eft, cond
//
//	  - priority: lower number wins (the policy_effect "priority(p.eft) || deny"
//	    keeps the first matching rule in priority-ascending order). The fixed
//	    ladder is exported as Priority* constants below.
//	  - eft: "allow" | "deny", always explicit on every emitted rule.
//	  - cond: an expr-lang (github.com/expr-lang/expr) expression evaluated by
//	    the abacEval custom function with the env {sub, dom, obj, act, roles,
//	    now}; "" short-circuits to true in the matcher, so plain RBAC rules
//	    never pay the ABAC cost.
//
// dom "*" is reserved for the super_admin seed; act "*" is wildcard on the
// policy side; obj matches exactly (no wildcard resources) except for the
// super_admin seed and per-app client/custom rules whose obj "*" must match
// too.
const ModelText = `[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = priority, sub, dom, obj, act, eft, cond

[role_definition]
g = _, _, _

[policy_effect]
e = priority(p.eft) || deny

[matchers]
m = (r.sub == p.sub || p.sub == "*" || g(r.sub, p.sub, r.dom) || g(r.sub, p.sub, "*")) && (r.dom == p.dom || p.dom == "*") && (r.obj == p.obj || p.obj == "*") && (r.act == p.act || p.act == "*") && (p.cond == "" || abacEval(p.cond, r.sub, r.dom, r.obj, r.act))
`

// Priority ladder (p.priority, ascending = evaluated first = wins). Every
// emitter (loader, incremental sync) MUST tag its rules with the ladder value
// matching its row type so deny/priority resolution stays deterministic:
//
//	super_admin wildcard   1   overrides everything
//	grant deny            20   direct deny on an account beats role allows
//	grant allow           30   direct allow beats role denies and custom rules
//	custom rule (default) 40   per-row overridable at CRUD time
//	role deny             45
//	role allow            50
//	client (service)      60
const (
	PrioritySuperAdmin        = 1
	PriorityGrantDeny         = 20
	PriorityGrantAllow        = 30
	PriorityCustomRuleDefault = 40
	PriorityRoleDeny          = 45
	PriorityRoleAllow         = 50
	PriorityClient            = 60
)

// Effect values (p.eft), always explicit.
const (
	EffectAllow = "allow"
	EffectDeny  = "deny"
)
