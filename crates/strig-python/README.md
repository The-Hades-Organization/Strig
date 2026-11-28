# strig-auth

Python binding for [Strig](https://github.com/The-Hades-Organization/Strig): the same engine and the same JSON
`EngineSpec` as the Rust and JavaScript APIs, as a native extension (PyO3, `abi3`, Python 3.9+).

```python
import strig

engine = strig.Engine(spec)
ctx = strig.Context(grants, now=1_700_000_000_000)
engine.check(ctx, {"subject": {"type": "user", "id": "u1"}, "permission": "doc.read",
                   "resource": {"type": "doc", "id": "d1"}})
```

See the repository README, section Python.
