package strig_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	strig "github.com/The-Hades-Organization/Strig/bindings/go"
)

var spec = map[string]any{
	"catalog": map[string]any{
		"targetKinds":  []string{"project"},
		"broadTargets": []string{"org"},
		"permissions": []map[string]any{
			{"key": "project.view", "targets": []string{"project"}},
			{"key": "project.edit", "targets": []string{"project"}},
		},
	},
}

func grant(id string, extra map[string]any) map[string]any {
	g := map[string]any{
		"id": id, "subject": map[string]any{"kind": "role", "id": "member"},
		"permission": "project.view", "target": map[string]any{"kind": "project"}, "effect": "allow",
	}
	for k, v := range extra {
		g[k] = v
	}
	return g
}

func request(permission, project string) map[string]any {
	return map[string]any{
		"subject":    map[string]any{"kind": "user", "id": "ana", "roles": []map[string]any{{"role": "member"}}},
		"permission": permission,
		"resource": map[string]any{"path": []map[string]any{
			{"kind": "project", "id": project}, {"kind": "org", "id": "o1"},
		}},
	}
}

func newEngine(t *testing.T) *strig.Engine {
	t.Helper()
	engine, err := strig.NewEngine(spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	return engine
}

func TestCheckDecideExplain(t *testing.T) {
	engine := newEngine(t)
	ctx, err := engine.NewContext(map[string]any{"grants": []any{
		grant("v", nil),
		grant("d", map[string]any{"effect": "deny", "target": map[string]any{"kind": "project", "id": "p2"}}),
	}})
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := engine.Check(ctx, request("project.view", "p1"))
	if err != nil || !allowed {
		t.Fatalf("p1 view: %v %v", allowed, err)
	}
	if allowed, _ = engine.Check(ctx, request("project.view", "p2")); allowed {
		t.Fatal("p2 is denied")
	}
	if allowed, _ = engine.Check(ctx, request("project.edit", "p1")); allowed {
		t.Fatal("edit is not granted")
	}
	decision, err := engine.Decide(ctx, request("project.view", "p1"))
	if err != nil || !decision.Allowed() {
		t.Fatalf("decide: %+v %v", decision, err)
	}
	explanation, err := engine.Explain(ctx, request("project.view", "p1"))
	if err != nil || explanation["permission"] != "project.view" {
		t.Fatalf("explain: %v %v", explanation, err)
	}
	many, err := engine.CheckMany(ctx, []any{request("project.view", "p1"), request("project.view", "p2")})
	if err != nil || len(many) != 2 || !many[0] || many[1] {
		t.Fatalf("checkMany: %v %v", many, err)
	}
}

func TestContextMutationShowsInNextDecision(t *testing.T) {
	engine := newEngine(t)
	ctx, _ := engine.NewContext(nil)
	if ok, _ := engine.Check(ctx, request("project.view", "p1")); ok {
		t.Fatal("empty context denies")
	}
	if err := ctx.AddGrant(grant("v", nil)); err != nil {
		t.Fatal(err)
	}
	if ok, _ := engine.Check(ctx, request("project.view", "p1")); !ok {
		t.Fatal("grant added")
	}
	if removed, err := ctx.RemoveGrant("v"); err != nil || !removed {
		t.Fatalf("remove: %v %v", removed, err)
	}
	if ok, _ := engine.Check(ctx, request("project.view", "p1")); ok {
		t.Fatal("grant removed")
	}
}

func TestGrantWindowFailsClosedWithoutNow(t *testing.T) {
	engine := newEngine(t)
	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	windowed := grant("w", map[string]any{"validUntil": now.Add(time.Hour).UnixMilli()})
	ctx, _ := engine.NewContext(map[string]any{"grants": []any{windowed}})
	if ok, _ := engine.Check(ctx, request("project.view", "p1")); ok {
		t.Fatal("a windowed allow without an instant must be ignored")
	}
	if ok, err := engine.Check(ctx, request("project.view", "p1"), strig.WithNow(now)); err != nil || !ok {
		t.Fatalf("inside the window: %v %v", ok, err)
	}
	if ok, _ := engine.Check(ctx, request("project.view", "p1"), strig.WithNow(now.Add(2*time.Hour))); ok {
		t.Fatal("after the window")
	}
}

func TestErrorsCarryTheStableCode(t *testing.T) {
	engine := newEngine(t)
	ctx, _ := engine.NewContext(nil)
	_, err := engine.Check(ctx, map[string]any{"permission": 3})
	if strig.CodeOf(err) != "INVALID_INPUT" {
		t.Fatalf("code = %q (%v)", strig.CodeOf(err), err)
	}
	var e *strig.Error
	if !errors.As(err, &e) || e.Message == "" {
		t.Fatalf("not an *Error: %v", err)
	}
	if _, err := strig.NewEngine(map[string]any{"bogus": 1}); strig.CodeOf(err) != "INVALID_INPUT" {
		t.Fatalf("bad spec: %v", err)
	}
}

func TestClosedAndForeignHandlesAreRefused(t *testing.T) {
	a, b := newEngine(t), newEngine(t)
	ctx, _ := a.NewContext(nil)
	if _, err := b.Check(ctx, request("project.view", "p1")); strig.CodeOf(err) != "INVALID_ARGUMENT" {
		t.Fatalf("foreign context: %v", err)
	}
	_ = ctx.Close()
	if ok, err := a.Check(ctx, request("project.view", "p1")); ok || err == nil {
		t.Fatalf("closed context must fail: %v %v", ok, err)
	}
	_ = a.Close()
	if ok, err := a.Check(ctx, request("project.view", "p1")); ok || err == nil {
		t.Fatalf("closed engine must fail: %v %v", ok, err)
	}
}

func TestListAndWhoCan(t *testing.T) {
	engine := newEngine(t)
	ctx, _ := engine.NewContext(map[string]any{"grants": []any{grant("v", nil)}})
	out, err := engine.List(ctx, request("x", "p1")["subject"], "project.view", "project", nil)
	if err != nil || out["kind"] != "project" {
		t.Fatalf("list: %v %v", out, err)
	}
	parties, err := engine.WhoCan(ctx, "project.view")
	if err != nil || len(parties) == 0 {
		t.Fatalf("whoCan: %v %v", parties, err)
	}
}

func TestApplyFillsTheHostClock(t *testing.T) {
	engine := newEngine(t)
	out, err := engine.Apply(map[string]any{})
	if err == nil {
		t.Fatalf("an empty change is not valid: %v", out)
	}
	if strig.CodeOf(err) != "INVALID_INPUT" {
		t.Fatalf("code = %q (%v): the clock must not be the reason", strig.CodeOf(err), err)
	}
}

func TestCompile(t *testing.T) {
	policy, err := strig.Compile("language blocks\n\ntarget_kinds = [org]\n\npermission org.read {\n  targets = [org]\n}\n")
	if err != nil || policy == nil {
		t.Fatalf("compile: %v %v", policy, err)
	}
	_, err = strig.Compile("language blocks\n\npermission {")
	var e *strig.Error
	if !errors.As(err, &e) || e.Code != "DSL_PARSE" || len(e.Diagnostics) == 0 {
		t.Fatalf("parse error: %v", err)
	}
}

func TestConcurrentUseAndFork(t *testing.T) {
	engine := newEngine(t)
	ctx, _ := engine.NewContext(map[string]any{"grants": []any{grant("v", nil)}})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if ok, err := engine.Check(ctx, request("project.view", "p1")); err != nil || !ok {
					t.Errorf("shared engine: %v %v", ok, err)
					return
				}
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fork, err := engine.Fork()
			if err != nil {
				t.Error(err)
				return
			}
			defer fork.Close()
			own, _ := fork.NewContext(map[string]any{"grants": []any{grant("v", nil)}})
			if ok, err := fork.Check(own, request("project.view", "p1")); err != nil || !ok {
				t.Errorf("fork: %v %v", ok, err)
			}
		}()
	}
	wg.Wait()
}
