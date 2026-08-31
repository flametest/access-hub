package casbinx

import (
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/flametest/vita/verrors"
)

// Enforcer wraps casbin.SyncedEnforcer with the access-hub model. Policy
// auto-load and auto-save are OFF: the full set is loaded explicitly from the
// read-only loader, and incremental updates are applied in-memory only (the
// business tables stay the single source of truth).
type Enforcer struct {
	e       *casbin.SyncedEnforcer
	watcher persist.Watcher
}

// NewEnforcer creates the enforcer with the given (read-only) adapter and
// performs the initial full policy load.
func NewEnforcer(loader persist.Adapter) (*Enforcer, error) {
	// Build the model from the embedded text (a plain string param would be
	// interpreted as a model file path).
	m, err := model.NewModelFromString(ModelText)
	if err != nil {
		return nil, verrors.Wrap(err, "parse casbin model")
	}
	e, err := casbin.NewSyncedEnforcer(m, loader)
	if err != nil {
		return nil, verrors.Wrap(err, "create casbin enforcer")
	}
	e.EnableAutoSave(false)
	if err := e.LoadPolicy(); err != nil {
		return nil, verrors.Wrap(err, "load casbin policies")
	}
	return &Enforcer{e: e}, nil
}

// normalizeDom aligns the domain argument with the loader's convention
// (`app:{key}`, or the literal "*"). Callers may pass a bare app key — the
// enforcer is the single place where the dom format is decided, so read and
// write paths can never drift apart.
func normalizeDom(dom string) string {
	if dom == "" || dom == DomWildcard || strings.HasPrefix(dom, DomPrefixApp) {
		return dom
	}
	return DomPrefixApp + dom
}

// Enforce evaluates the request (sub, dom, obj, act). Fail-close: an internal
// error yields (false, err), never an allow.
func (en *Enforcer) Enforce(sub, dom, obj, act string) (bool, error) {
	dom = normalizeDom(dom)
	ok, err := en.e.Enforce(sub, dom, obj, act)
	if err != nil {
		return false, verrors.Wrap(err, fmt.Sprintf("enforce %s@%s:%s:%s", sub, dom, obj, act))
	}
	return ok, nil
}

// Reload performs a full policy re-load from the loader (startup, watcher
// notifications, or after bootstrap mutations).
func (en *Enforcer) Reload() error {
	if err := en.e.LoadPolicy(); err != nil {
		return verrors.Wrap(err, "reload casbin policies")
	}
	return nil
}

// AddPolicy applies an incremental p rule in-memory (no storage). The dom
// term (rule[1]) is normalized like Enforce.
func (en *Enforcer) AddPolicy(rule ...string) (bool, error) {
	params := make([]interface{}, len(rule))
	for i, r := range rule {
		params[i] = r
	}
	if len(params) >= 2 {
		params[1] = normalizeDom(params[1].(string))
	}
	ok, err := en.e.AddPolicy(params...)
	if err != nil {
		return false, verrors.Wrap(err, "add policy")
	}
	return ok, nil
}

// RemovePolicy removes a p rule in-memory (no storage). The dom term
// (rule[1]) is normalized like Enforce.
func (en *Enforcer) RemovePolicy(rule ...string) (bool, error) {
	params := make([]interface{}, len(rule))
	for i, r := range rule {
		params[i] = r
	}
	if len(params) >= 2 {
		params[1] = normalizeDom(params[1].(string))
	}
	ok, err := en.e.RemovePolicy(params...)
	if err != nil {
		return false, verrors.Wrap(err, "remove policy")
	}
	return ok, nil
}

// AddGroupingPolicy applies an incremental g rule (role binding) in-memory.
// The dom term (rule[2]) is normalized like Enforce.
func (en *Enforcer) AddGroupingPolicy(rule ...string) (bool, error) {
	params := make([]interface{}, len(rule))
	for i, r := range rule {
		params[i] = r
	}
	if len(params) >= 3 {
		params[2] = normalizeDom(params[2].(string))
	}
	ok, err := en.e.AddGroupingPolicy(params...)
	if err != nil {
		return false, verrors.Wrap(err, "add grouping policy")
	}
	return ok, nil
}

// RemoveGroupingPolicy removes a g rule in-memory. The dom term (rule[2])
// is normalized like Enforce.
func (en *Enforcer) RemoveGroupingPolicy(rule ...string) (bool, error) {
	params := make([]interface{}, len(rule))
	for i, r := range rule {
		params[i] = r
	}
	if len(params) >= 3 {
		params[2] = normalizeDom(params[2].(string))
	}
	ok, err := en.e.RemoveGroupingPolicy(params...)
	if err != nil {
		return false, verrors.Wrap(err, "remove grouping policy")
	}
	return ok, nil
}

// SetWatcher attaches the reload watcher; its callback triggers Reload.
func (en *Enforcer) SetWatcher(w persist.Watcher) error {
	if err := en.e.SetWatcher(w); err != nil {
		return verrors.Wrap(err, "set casbin watcher")
	}
	en.watcher = w
	return nil
}

// NotifyReload publishes a reload broadcast to all instances (no-op when no
// watcher is wired, e.g. in tests).
func (en *Enforcer) NotifyReload() error {
	if en.watcher == nil {
		return nil
	}
	return en.watcher.Update()
}
