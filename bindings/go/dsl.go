package strig

import (
	"encoding/json"
	"sync"
)

var (
	dslMu     sync.Mutex
	dslEngine *Engine
)

// dsl runs a policy-language operation on a shared instance that carries no engine state.
func dsl(op string, args map[string]any, out any) error {
	dslMu.Lock()
	if dslEngine == nil {
		engine, err := newEngine(json.RawMessage(`{"catalog":{"targetKinds":[],"broadTargets":[],"permissions":[]}}`))
		if err != nil {
			dslMu.Unlock()
			return err
		}
		dslEngine = engine
	}
	engine := dslEngine
	dslMu.Unlock()
	return engine.invoke(op, args, out)
}

// Compile turns policy-language text into the policy JSON (the same document Engine takes as its
// spec after loading). A syntax error is DSL_PARSE and an invalid policy DSL_VALIDATE; both carry
// Diagnostics.
func Compile(text string, file ...string) (map[string]any, error) {
	args := map[string]any{"text": text}
	if len(file) > 0 {
		args["options"] = map[string]any{"file": file[0]}
	}
	var out map[string]any
	err := dsl("dsl.compile", args, &out)
	return out, err
}

// Format returns text in the canonical layout.
func Format(text string) (string, error) {
	var out string
	err := dsl("dsl.format", map[string]any{"text": text}, &out)
	return out, err
}
