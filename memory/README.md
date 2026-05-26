# Hunt Memory

Persistent, target-scoped knowledge store for the autonomous orchestration
layer. Written and read via [`../scripts/memory.py`](../scripts/memory.py).
Every record carries a `bundle_id` so one store serves many apps — the layer
is **never fixed to a single target**.

JSONL files here are runtime artifacts and are git-ignored (except this README).

## Stores

| File | Purpose | Read by |
|------|---------|---------|
| `audit.jsonl` | Validated findings + impact | `/report`, `/pickup` |
| `patterns.jsonl` | Techniques that produced a finding (cross-target) | `/recon` ranking, `/hunt` |
| `journal.jsonl` | Session events + untested attack surface | `/pickup` |

## Record shapes

`audit.jsonl`
```json
{"bundle_id":"com.example.app","ts":"...","title":"Token in NSUserDefaults",
 "masvs":"STORAGE-1","severity":"high","evidence":"defaults key auth_token",
 "validated":true,"impact":"Account takeover if device compromised"}
```

`patterns.jsonl`
```json
{"bundle_id":"com.example.app","ts":"...","technique":"fuzz path idor_numeric",
 "tool":"fuzz","surface":"GET /api/v2/users/{id}","worked":true}
```

`journal.jsonl`
```json
{"bundle_id":"com.example.app","ts":"...","phase":"hunt","mode":"normal",
 "note":"completed storage+network","untested":["scheme exampleapp://pay","WKWebView eval"]}
```

## CLI

```bash
python scripts/memory.py log audit    --bundle com.x --json '{"title":"...","severity":"high"}'
python scripts/memory.py query audit  --bundle com.x --limit 20
python scripts/memory.py resume       --bundle com.x      # used by /pickup
python scripts/memory.py stats
```

Files auto-rotate at 10 MB, keeping 3 backups. Override location with
`FRIDA_MEMORY_DIR`.
