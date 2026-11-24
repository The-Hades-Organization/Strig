// tsc does not copy hand-written declarations: index.d.ts is the public type of the native/wasm binding.
import { copyFileSync } from 'node:fs';

copyFileSync(new URL('../src/index.d.ts', import.meta.url), new URL('../dist/index.d.ts', import.meta.url));
