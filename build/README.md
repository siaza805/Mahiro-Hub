# Build / obfuscation

The published `MahiroHub.lua` is an obfuscated build. It decodes and runs
itself at load time, so the HTTP loader keeps working unchanged:

```lua
loadstring(game:HttpGet("https://raw.githubusercontent.com/siaza805/Mahiro-Hub/main/MahiroHub.lua?v=obf-1"))()
```

## Active build: `obfuscate.py` v2 (multi-layer encoder)

The published `MahiroHub.lua` is produced by `obfuscate.py`. It decodes once at
load time and then runs the original code at native speed, so there is no
per-frame runtime overhead — important on mobile. The Prometheus VM build below
is much stronger but its bytecode interpreter made the script lag badly on
phones, so it is not the active build.

v2 strengthens the at-rest file without adding any runtime cost:
- five byte layers (add / sub keystreams + a forward and a backward CBC chain),
  so every plaintext byte is diffused across the whole ciphertext both ways;
- substitution over a shuffled hex alphabet, then a keyed chunk-order shuffle;
- an anti-tamper gate: the layer seeds are stored as `seed - H`, where `H` is a
  hash of the stored ciphertext, so editing one byte of the blob makes every
  seed wrong and decoding fails;
- three nested stages — the real decoder is buried under two encoded layers, so
  the top file shows only the blob and a tiny bootstrap.

Arithmetic only (no `bit32` / bitwise ops), so the same decoder runs on Luau and
stock Lua; every build is verified byte-exact (SHA-256) and run on a real Luau
runtime before publishing.

## Stronger (but slow on mobile): Prometheus (free, open source)

The VM build is produced with **Prometheus** (https://github.com/levno-710/Prometheus),
a free, open-source Lua/Luau obfuscator. Pipeline (see `prometheus_config.lua`):

| Step            | Effect |
|-----------------|--------|
| `Vmify`         | compiles the script into a custom bytecode VM (the heavy layer) |
| `EncryptStrings`| encrypts all string literals |
| `Cff`           | control-flow flattening |
| `ConstantArray` | moves constants into a shuffled + rotated array |
| `WrapInFunction`| wraps the whole chunk |

Target is `--LuaU`. `AntiTamper` and `NumbersToExpressions` are intentionally
**excluded** — on Luau they break at runtime (AntiTamper relies on
`string.dump`, which Luau does not have; NumbersToExpressions after
ConstantArray produced a non-runnable result in testing).

### Luau source fixes required before obfuscation

Prometheus' Luau parser is incomplete. The source must be adjusted first, with
no change in behaviour:

1. `continue` used as a **field/method name** (not the loop statement) must be
   renamed, because Prometheus treats `continue` as a hard keyword. In this
   project that was `M.continue` / `s.continue` / a `continue =` table key →
   renamed to `continueDlg`.
2. The floor-division operator `//` is unsupported → rewrite `a // b` as
   `math.floor(a / b)` (equivalent for the non-negative operands used here).

Real backtick string interpolation is also unsupported, but here all backticks
live inside comments, which Prometheus strips, so no change was needed.

### Rebuild

```sh
git clone https://github.com/levno-710/Prometheus
lua Prometheus/cli.lua --config build/prometheus_config.lua --LuaU \
    --out MahiroHub.lua <your-source>.lua
```

Then prepend the `--!nocheck` header. Verify on a real Luau runtime
(https://github.com/luau-lang/luau) before publishing.

## Alternative: `obfuscate.py`

`obfuscate.py` is a self-contained multi-layer string encoder (LCG keystreams +
feedback chain + shuffled-hex + chunk shuffle + two-stage loader). Lighter and
much smaller output than the VM build, but weaker. Kept as a fallback.

## Honest limitations

- **Any self-contained obfuscation is reversible.** The file must decrypt
  itself to run, so the key is in the file; anyone who can run or trace it can
  recover the source (e.g. by hooking `loadstring`). This includes Prometheus —
  public Prometheus deobfuscators exist. Obfuscation raises cost, it does not
  make code secret.
- The **plaintext source still exists in this repo's git history**. Obfuscating
  the current file does not remove it; history must be rewritten to do that.
