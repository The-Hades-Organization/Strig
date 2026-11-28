package strig

import (
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"fmt"
	"io"
	"sync"

	"github.com/tetratelabs/wazero"
)

// The engine compiled to WebAssembly by crates/strig-wasi, gzipped to keep the repository small.
//
//go:embed strig.wasm.gz
var wasmGzip []byte

var (
	loadOnce sync.Once
	loadErr  error
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
)

// load decompresses and compiles the module once per process; every Engine instantiates it.
func load(ctx context.Context) (wazero.Runtime, wazero.CompiledModule, error) {
	loadOnce.Do(func() {
		reader, err := gzip.NewReader(bytes.NewReader(wasmGzip))
		if err != nil {
			loadErr = fmt.Errorf("strig: embedded module: %w", err)
			return
		}
		raw, err := io.ReadAll(reader)
		if err != nil {
			loadErr = fmt.Errorf("strig: embedded module: %w", err)
			return
		}
		runtime = wazero.NewRuntime(ctx)
		compiled, loadErr = runtime.CompileModule(ctx, raw)
		if loadErr != nil {
			loadErr = fmt.Errorf("strig: compile module: %w", loadErr)
		}
	})
	return runtime, compiled, loadErr
}
