// Package strig is the Go binding of the Strig authorization engine. It runs the same engine
// compiled to WebAssembly on wazero (pure Go, no cgo), with the same JSON spec, the same
// decisions and the same error codes as the Rust, JavaScript and Python APIs.
package strig

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/tetratelabs/wazero/api"
)

// Engine is one engine instance over a spec. It is safe for concurrent use: calls are serialized
// by a mutex, because a WebAssembly instance is single-threaded. For parallel throughput give each
// worker its own engine with Fork.
type Engine struct {
	mu     sync.Mutex
	spec   json.RawMessage
	mod    api.Module
	alloc  api.Function
	free   api.Function
	call   api.Function
	handle uint64
	closed bool
	broken bool
	opts   options
}

// Context holds the grants, tuples, environment and instant of the decisions of one Engine.
type Context struct {
	engine *Engine
	handle uint64
	closed bool
}

type options struct {
	now *uint64
}

// Option changes one call.
type Option func(*options)

// WithNow sets the instant of one call, overriding the context's. Without any instant the engine
// fails closed: an allow with a validity window is ignored and a deny with one stands.
func WithNow(t time.Time) Option {
	ms := uint64(t.UnixMilli())
	return func(o *options) { o.now = &ms }
}

// NewEngine builds an engine from spec, anything encoding/json turns into the EngineSpec JSON
// (a map, a struct, a json.RawMessage).
func NewEngine(spec any) (*Engine, error) {
	raw, err := json.Marshal(spec)
	if err != nil {
		return nil, &Error{Code: "INVALID_ARGUMENT", Message: "spec is not JSON: " + err.Error()}
	}
	return newEngine(raw)
}

func newEngine(spec json.RawMessage) (*Engine, error) {
	ctx := context.Background()
	rt, module, err := load(ctx)
	if err != nil {
		return nil, err
	}
	mod, err := rt.InstantiateModule(ctx, module, moduleConfig())
	if err != nil {
		return nil, fmt.Errorf("strig: instantiate module: %w", err)
	}
	e := &Engine{
		spec:  spec,
		mod:   mod,
		alloc: mod.ExportedFunction("strig_alloc"),
		free:  mod.ExportedFunction("strig_free"),
		call:  mod.ExportedFunction("strig_call"),
	}
	var handle uint64
	if err := e.invoke("engine.new", map[string]any{"spec": spec}, &handle); err != nil {
		_ = mod.Close(ctx)
		return nil, err
	}
	e.handle = handle
	return e, nil
}

// Fork returns an independent engine over the same spec, with its own instance and no shared
// state, for another goroutine.
func (e *Engine) Fork() (*Engine, error) {
	return newEngine(e.spec)
}

// Close releases the instance. Contexts of the engine become unusable.
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	return e.mod.Close(context.Background())
}

// NewContext creates a context. init is the optional {grants, tuples, env, now, limits} object.
func (e *Engine) NewContext(init any) (*Context, error) {
	var handle uint64
	if err := e.invoke("context.new", map[string]any{"init": init}, &handle); err != nil {
		return nil, err
	}
	return &Context{engine: e, handle: handle}, nil
}

// Close releases the context.
func (c *Context) Close() error {
	c.engine.mu.Lock()
	closed := c.closed || c.engine.closed
	c.engine.mu.Unlock()
	if closed {
		return nil
	}
	err := c.engine.invoke("context.free", map[string]any{"context": c.handle}, nil)
	c.engine.mu.Lock()
	c.closed = true
	c.engine.mu.Unlock()
	return err
}

func (c *Context) op(name string, extra map[string]any, out any) error {
	if extra == nil {
		extra = map[string]any{}
	}
	extra["context"] = c.handle
	return c.engine.invokeCtx(c, name, extra, out)
}

// SetGrants replaces every grant of the context.
func (c *Context) SetGrants(grants any) error {
	return c.op("context.setGrants", map[string]any{"grants": grants}, nil)
}

// AddGrant adds or replaces (by id) one grant.
func (c *Context) AddGrant(grant any) error {
	return c.op("context.addGrant", map[string]any{"grant": grant}, nil)
}

// RemoveGrant removes a grant by id and reports whether it existed.
func (c *Context) RemoveGrant(id string) (bool, error) {
	var removed bool
	err := c.op("context.removeGrant", map[string]any{"id": id}, &removed)
	return removed, err
}

// Grants returns the grants of the context.
func (c *Context) Grants() ([]map[string]any, error) {
	var grants []map[string]any
	err := c.op("context.grants", nil, &grants)
	return grants, err
}

// AddTuple adds a relationship tuple and reports whether it was new.
func (c *Context) AddTuple(tuple any) (bool, error) {
	var added bool
	err := c.op("context.addTuple", map[string]any{"tuple": tuple}, &added)
	return added, err
}

// RemoveTuple removes a relationship tuple and reports whether it existed.
func (c *Context) RemoveTuple(tuple any) (bool, error) {
	var removed bool
	err := c.op("context.removeTuple", map[string]any{"tuple": tuple}, &removed)
	return removed, err
}

// SetEnv replaces the environment attributes.
func (c *Context) SetEnv(env any) error {
	return c.op("context.setEnv", map[string]any{"env": env}, nil)
}

// SetNow fixes the instant of the context's decisions, in epoch milliseconds.
func (c *Context) SetNow(t time.Time) error {
	return c.op("context.setNow", map[string]any{"now": t.UnixMilli()}, nil)
}

// SetLimits sets the query limits ({maxResults, ...}) of the context.
func (c *Context) SetLimits(limits any) error {
	return c.op("context.setLimits", map[string]any{"limits": limits}, nil)
}

func (e *Engine) decisionOp(op string, c *Context, request any, out any, opts []Option) error {
	args := map[string]any{"context": c.handle, "request": request}
	applyOptions(args, opts)
	return e.invokeCtx(c, op, args, out)
}

func applyOptions(args map[string]any, opts []Option) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	if o.now != nil {
		args["now"] = *o.now
	}
}

// Check reports whether request is allowed. Any failure to decide is an error and never true.
func (e *Engine) Check(c *Context, request any, opts ...Option) (bool, error) {
	var allowed bool
	if err := e.decisionOp("check", c, request, &allowed, opts); err != nil {
		return false, err
	}
	return allowed, nil
}

// Decision is the answer of Decide.
type Decision struct {
	Effect   string          `json:"effect"`
	Reason   json.RawMessage `json:"reason"`
	Matched  []string        `json:"matched,omitempty"`
	Warnings []string        `json:"warnings,omitempty"`
}

// Allowed reports whether the effect is allow.
func (d Decision) Allowed() bool { return d.Effect == "allow" }

// Decide answers a request with its effect and reason.
func (e *Engine) Decide(c *Context, request any, opts ...Option) (*Decision, error) {
	var decision Decision
	if err := e.decisionOp("decide", c, request, &decision, opts); err != nil {
		return nil, err
	}
	return &decision, nil
}

// Explain answers a request with the full explanation (effective grants, path, why).
func (e *Engine) Explain(c *Context, request any, opts ...Option) (map[string]any, error) {
	var out map[string]any
	err := e.decisionOp("explain", c, request, &out, opts)
	return out, err
}

// CheckMany answers each request, in order.
func (e *Engine) CheckMany(c *Context, requests any, opts ...Option) ([]bool, error) {
	args := map[string]any{"context": c.handle, "requests": requests}
	applyOptions(args, opts)
	var out []bool
	if err := e.invokeCtx(c, "checkMany", args, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// List describes what subject can reach with permission over resources of kind. options is the
// optional {layout, resources} object.
func (e *Engine) List(c *Context, subject any, permission, kind string, options any, opts ...Option) (map[string]any, error) {
	args := map[string]any{"context": c.handle, "subject": subject, "permission": permission, "kind": kind, "options": options}
	applyOptions(args, opts)
	var out map[string]any
	err := e.invokeCtx(c, "list", args, &out)
	return out, err
}

// WhoCan names the parties some allow grant gives permission to.
func (e *Engine) WhoCan(c *Context, permission string, opts ...Option) ([]map[string]any, error) {
	args := map[string]any{"context": c.handle, "permission": permission}
	applyOptions(args, opts)
	var out []map[string]any
	err := e.invokeCtx(c, "whoCan", args, &out)
	return out, err
}

// Catalog returns the permission catalog of the spec.
func (e *Engine) Catalog() (map[string]any, error) {
	var out map[string]any
	err := e.invoke("catalog", map[string]any{}, &out)
	return out, err
}

// Apply applies a grant or role change through the invariants and returns
// {ok, grants?, subject?, violations?, audit?}. When input has no "now", the host clock fills it.
func (e *Engine) Apply(input any) (map[string]any, error) {
	return e.change("apply", input)
}

// Propose, Resolve and Expire drive the approval flow like Apply.
func (e *Engine) Propose(input any) (map[string]any, error) { return e.change("propose", input) }
func (e *Engine) Resolve(input any) (map[string]any, error) { return e.change("resolve", input) }
func (e *Engine) Expire(input any) (map[string]any, error)  { return e.change("expire", input) }

func (e *Engine) change(op string, input any) (map[string]any, error) {
	raw, err := json.Marshal(input)
	if err != nil {
		return nil, &Error{Code: "INVALID_ARGUMENT", Message: "input is not JSON: " + err.Error()}
	}
	var out map[string]any
	err = e.invoke(op, map[string]any{"input": json.RawMessage(raw), "now": hostNow(raw)}, &out)
	return out, err
}

// hostNow is the host clock, used when the input carries no instant of its own.
func hostNow(input json.RawMessage) any {
	var probe struct {
		Now json.RawMessage `json:"now"`
	}
	if json.Unmarshal(input, &probe) == nil && len(probe.Now) > 0 && string(probe.Now) != "null" {
		return nil
	}
	return uint64(time.Now().UnixMilli())
}

func (e *Engine) invokeCtx(c *Context, op string, args map[string]any, out any) error {
	if c == nil || c.engine != e {
		return &Error{Code: "INVALID_ARGUMENT", Message: "context belongs to another engine"}
	}
	e.mu.Lock()
	closed := c.closed
	e.mu.Unlock()
	if closed {
		return ErrClosed
	}
	args["engine"] = e.handle
	return e.invoke(op, args, out)
}

type envelope struct {
	Ok          bool            `json:"ok"`
	Value       json.RawMessage `json:"value"`
	Code        string          `json:"code"`
	Message     string          `json:"message"`
	Diagnostics []any           `json:"diagnostics"`
}

func (e *Engine) invoke(op string, args map[string]any, out any) error {
	if op != "engine.new" {
		args["engine"] = e.handle
	}
	body, err := json.Marshal(args)
	if err != nil {
		return &Error{Code: "INVALID_ARGUMENT", Message: "argument is not JSON: " + err.Error()}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	answer, err := e.roundTrip(op, body)
	if err != nil {
		return err
	}
	var env envelope
	if err := json.Unmarshal(answer, &env); err != nil {
		return &Error{Code: "INTERNAL", Message: "unreadable answer: " + err.Error()}
	}
	if !env.Ok {
		return &Error{Code: env.Code, Message: env.Message, Diagnostics: env.Diagnostics}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(env.Value, out); err != nil {
		return &Error{Code: "INTERNAL", Message: "unexpected answer shape: " + err.Error()}
	}
	return nil
}

// roundTrip copies the operation and the input into guest memory, calls strig_call and copies the
// answer out. Callers hold e.mu.
func (e *Engine) roundTrip(op string, body []byte) ([]byte, error) {
	if e.closed {
		return nil, ErrClosed
	}
	if e.broken {
		return nil, ErrBroken
	}
	ctx := context.Background()
	opPtr, err := e.put(ctx, []byte(op))
	if err != nil {
		return nil, err
	}
	inPtr, err := e.put(ctx, body)
	if err != nil {
		e.release(ctx, opPtr, uint64(len(op)))
		return nil, err
	}
	defer e.release(ctx, opPtr, uint64(len(op)))
	defer e.release(ctx, inPtr, uint64(len(body)))
	packed, err := e.call.Call(ctx, opPtr, uint64(len(op)), inPtr, uint64(len(body)))
	if err != nil {
		e.broken = true
		return nil, ErrBroken
	}
	ptr, length := uint32(packed[0]>>32), uint32(packed[0])
	data, ok := e.mod.Memory().Read(ptr, length)
	if !ok {
		e.broken = true
		return nil, ErrBroken
	}
	answer := append([]byte(nil), data...)
	e.release(ctx, uint64(ptr), uint64(length))
	return answer, nil
}

func (e *Engine) put(ctx context.Context, data []byte) (uint64, error) {
	res, err := e.alloc.Call(ctx, uint64(len(data)))
	if err != nil {
		e.broken = true
		return 0, ErrBroken
	}
	if !e.mod.Memory().Write(uint32(res[0]), data) {
		e.broken = true
		return 0, ErrBroken
	}
	return res[0], nil
}

func (e *Engine) release(ctx context.Context, ptr, length uint64) {
	if _, err := e.free.Call(ctx, ptr, length); err != nil {
		e.broken = true
	}
}
