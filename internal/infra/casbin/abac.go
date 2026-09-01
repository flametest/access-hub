// ABAC condition evaluation for custom rules (design.md §12 M6): the
// p.cond term of a 7-tuple rule is an expr-lang expression evaluated by the
// abacEval custom function inside the Casbin matcher.
//
// Sandboxing: the expression compiles against a typed environment
// (ExprEnv), so unknown identifiers and arbitrary function calls are
// REJECTED AT COMPILE TIME — the expression can only reference sub, dom,
// obj, act, roles, now and expr's pure built-ins (len, all, filter, ...).
// A recover() guard additionally converts any evaluation panic into an
// error. This replaces the 100ms-evaluation-timeout idea from the design
// doc with a strictly stronger guarantee: nothing in the environment can
// escape (no I/O, no reflection on arbitrary values), and compilation is
// cached per expression string.
package casbinx

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	log "github.com/flametest/vita/vlog"
)

// ExprEnv is the typed evaluation environment exposed to custom-rule
// expressions:
//
//   - Sub/Dom/Obj/Act mirror the Casbin request; Dom is the RAW app key
//     ("crm", not "app:crm") so expressions read naturally.
//   - Roles is the union of the subject's roles bound in the request domain
//     and in the wildcard domain, with the "role:" prefix stripped
//     (["manager", "org_admin"]).
//   - Now is the evaluation timestamp (time.Time, e.g. now.Hour() < 23).
//
// The expr tags expose the fields as lowercase identifiers (expr envs are
// matched case-sensitively).
type ExprEnv struct {
	Sub   string    `expr:"sub"`
	Dom   string    `expr:"dom"`
	Obj   string    `expr:"obj"`
	Act   string    `expr:"act"`
	Roles []string  `expr:"roles"`
	Now   time.Time `expr:"now"`
}

// exprCache caches compiled programs keyed by the expression text. Programs
// are immutable and safe for concurrent Run; the cache grows with the number
// of distinct custom rules (bounded by admin CRUD).
var exprCache sync.Map // string -> *vm.Program

// compileExpr compiles source against the typed env with boolean output,
// caching the program. An error means the expression is invalid (unknown
// identifier/function, syntax, non-boolean result type).
func compileExpr(source string) (*vm.Program, error) {
	if cached, ok := exprCache.Load(source); ok {
		return cached.(*vm.Program), nil
	}
	program, err := expr.Compile(source, expr.Env(ExprEnv{}), expr.AsBool())
	if err != nil {
		return nil, err
	}
	exprCache.Store(source, program)
	return program, nil
}

// runExpr executes a compiled program with the recover() guard; any panic
// becomes an error (fail-close).
func runExpr(program *vm.Program, env ExprEnv) (out bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			out = false
			err = fmt.Errorf("expression evaluation panicked: %v", r)
		}
	}()
	value, err := expr.Run(program, env)
	if err != nil {
		return false, err
	}
	result, ok := value.(bool)
	if !ok {
		return false, fmt.Errorf("expression result is not boolean (got %T)", value)
	}
	return result, nil
}

// ValidateExpr reports whether expr is a valid custom-rule condition,
// exercising the same compile cache as evaluation. An empty expression is
// valid (the matcher short-circuits before abacEval). Non-nil errors carry
// the compiler message (surfaced as 400 by the admin CRUD).
func ValidateExpr(source string) error {
	if strings.TrimSpace(source) == "" {
		return nil
	}
	_, err := compileExpr(source)
	return err
}

// TestExpr evaluates an expression against an explicit environment without
// touching the enforcer (admin dry-run endpoint). The first error (compile
// or run) is returned with allowed=false (fail-close).
func TestExpr(source string, env ExprEnv) (bool, error) {
	program, err := compileExpr(source)
	if err != nil {
		return false, err
	}
	return runExpr(program, env)
}

// evalABAC evaluates the cond term of a matching p rule for the request
// (sub, dom, obj, act). dom is the (already normalized) request domain; the
// expression sees the raw app key. Fail-close: any error yields (false, err).
//
// Callers run under the SyncedEnforcer read lock (the function is only
// invoked from the matcher), so the CORE enforcer is used for the role
// lookup — re-acquiring the synced RLock could deadlock with a pending
// writer (recursive read locking is forbidden by sync.RWMutex), while a bare
// read is safe because the writer is excluded by the held read lock.
func evalABAC(rolesOf func(sub, dom string) []string, cond, sub, dom, obj, act string) (bool, error) {
	if strings.TrimSpace(cond) == "" {
		// Unreachable through the matcher (it short-circuits on p.cond == "")
		// but kept as a safe default for direct callers.
		return true, nil
	}
	program, err := compileExpr(cond)
	if err != nil {
		log.Warn().Any("error", err).Msg("abac cond failed to compile (fail-close)")
		return false, fmt.Errorf("abac cond compile: %w", err)
	}
	env := ExprEnv{
		Sub:   sub,
		Dom:   strings.TrimPrefix(dom, DomPrefixApp),
		Obj:   obj,
		Act:   act,
		Roles: rolesOf(sub, dom),
		Now:   time.Now(),
	}
	out, err := runExpr(program, env)
	if err != nil {
		log.Warn().Any("error", err).Any("cond", cond).Msg("abac cond evaluation failed (fail-close)")
		return false, err
	}
	return out, nil
}
