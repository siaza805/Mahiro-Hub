#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mahiro Hub multi-layer obfuscator (v2).

Takes a plaintext Luau source file and emits a heavily obfuscated, still-runnable
single file. The payload is NEVER parsed; it is treated as opaque bytes, encoded
through several reversible layers, and reconstructed + loadstring()'d at runtime.
After the one-time decode the ORIGINAL code runs, so there is no per-frame runtime
overhead (unlike a bytecode VM) -- important on mobile.

Design goals of v2 (strength added only at load/decode time, never at runtime):

  5 byte layers, arithmetic only (no bit32 / bitwise ops) so the exact decoder
  runs on Luau and stock Lua alike:
    L1  add  keystream        (LCG A)
    L2  forward  CBC add-chain (LCG B, IVb)  -- each byte depends on all earlier
    L3  sub  keystream        (LCG C)
    L4  backward CBC add-chain (LCG D, IVd)  -- each byte depends on all later
    L5  add  keystream        (LCG E)
  The two CBC chains diffuse every plaintext byte across the whole ciphertext in
  both directions, so byte-local or chunk-reordering analysis gets no foothold.

  Serialization: bytes -> 2 symbols from a shuffled 16-char alphabet (substitution,
  not plain hex), split into chunks whose order is shuffled by a keyed Fisher-Yates.

  Anti-tamper gate: the five layer seeds are not stored directly. Each is stored as
  (seed - H) where H is a hash over the exact stored ciphertext text. The decoder
  recomputes H and recovers the seeds; editing a single byte of the blob changes H,
  so every seed comes out wrong and the payload fails to decode. Raises the cost of
  patching the distribution in place.

  Three nested stages: the real decoder (stage 3) is encoded into stage 2, which is
  encoded into a tiny visible stage-1 bootstrap. Reading the top file shows only the
  ciphertext blob + a micro-loader; the actual algorithm is buried under two encoded
  layers.

Honest limit: any self-contained obfuscation is reversible -- the file must decode
itself to run, so hooking loadstring recovers the source. This raises cost, it does
not make code secret.
"""

import os
import sys
import random
import argparse

MASK32 = 0x100000000
LCG_A = 1664525
LCG_C = 1013904223
HMOD = 16777216  # 2**24


class LCG:
    def __init__(self, seed):
        self.s = seed % MASK32

    def nextbyte(self):
        self.s = (self.s * LCG_A + LCG_C) % MASK32
        return (self.s // 65536) % 256

    def nextint(self):
        self.s = (self.s * LCG_A + LCG_C) % MASK32
        return self.s


# ---- byte layers (encode) ------------------------------------------------- #
def enc_add(data, seed):
    g = LCG(seed)
    return bytes((b + g.nextbyte()) % 256 for b in data)


def enc_sub(data, seed):
    g = LCG(seed)
    return bytes((b - g.nextbyte()) % 256 for b in data)


def enc_fwd_cbc(data, seed, iv):
    g = LCG(seed)
    out = bytearray(len(data))
    prev = iv
    for i, b in enumerate(data):
        c = (b + g.nextbyte() + prev) % 256
        out[i] = c
        prev = c
    return bytes(out)


def enc_bwd_cbc(data, seed, iv):
    # keystream consumed in index order 1..n (so the decoder can run forward);
    # chaining references the NEXT ciphertext byte (iv past the end).
    n = len(data)
    ks = [LCG(seed).nextbyte() for _ in range(0)]  # placeholder (unused)
    g = LCG(seed)
    ksarr = [g.nextbyte() for _ in range(n)]
    out = bytearray(n)
    nxt = iv
    for i in range(n - 1, -1, -1):
        c = (data[i] + ksarr[i] + nxt) % 256
        out[i] = c
        nxt = c
    return bytes(out)


def texthash(s):
    h = 0
    for ch in s.encode("latin-1"):
        h = (h * 33 + ch) % HMOD
    return h


def serialize(data, alphabet):
    out = []
    for b in data:
        out.append(alphabet[b >> 4])
        out.append(alphabet[b & 0x0F])
    return "".join(out)


def fisher_yates_perm(n, seed):
    g = LCG(seed)
    a = list(range(n))
    i = n - 1
    while i >= 1:
        j = g.nextint() % (i + 1)
        a[i], a[j] = a[j], a[i]
        i -= 1
    return a


def chunk_shuffle(text, chunk_size, seed):
    chunks = [text[i:i + chunk_size] for i in range(0, len(text), chunk_size)]
    n = len(chunks)
    perm = fisher_yates_perm(n, seed)
    return [chunks[perm[i]] for i in range(n)]


def lua_str(s):
    level = 0
    while ("]" + "=" * level + "]") in s or ("[" + "=" * level + "[") in s:
        level += 1
    eq = "=" * level
    return "[" + eq + "[" + s + "]" + eq + "]"


# --------------------------------------------------------------------------- #
# Stage 3: the real decoder. function(D) -> reconstruct + run the payload.     #
# --------------------------------------------------------------------------- #
STAGE3 = r"""
return function(D)
  local A,C,M,HM = {A_},{C_},{M_},{HM_}
  local function lcg(seed)
    local s=seed%M
    return function() s=(s*A+C)%M return (math.floor(s/65536))%256 end
  end
  local function lcgi(sd)
    local s=sd%M
    return function() s=(s*A+C)%M return s end
  end
  local ALPHA={ALPHA_}
  local inv={}
  for i=1,16 do inv[string.byte(ALPHA,i)]=i-1 end
  -- stored text (shuffled chunk order) -> anti-tamper hash
  local stored=table.concat(D.k)
  local sb=string.byte
  local H=0
  for i=1,#stored do H=(H*33+sb(stored,i))%HM end
  local function seed(base) return (base+H)%M end
  -- undo chunk shuffle
  local chunks=D.k
  local n=#chunks
  local a={}
  for i=1,n do a[i]=i-1 end
  do
    local g=lcgi(seed({SD_}))
    local i=n
    while i>=2 do local j=(g()%i)+1 a[i],a[j]=a[j],a[i] i=i-1 end
  end
  local ordered={}
  for i=1,n do ordered[a[i]+1]=chunks[i] end
  local text=table.concat(ordered)
  -- symbols -> bytes
  local blen=math.floor(#text/2)
  local b={}
  for i=1,blen do b[i]=inv[sb(text,2*i-1)]*16+inv[sb(text,2*i)] end
  -- undo L5 (add E)
  do local g=lcg(seed({SE_})) for i=1,blen do b[i]=(b[i]-g())%256 end end
  -- undo L4 (backward CBC): x3[i] = c[i]-ksD[i]-c[i+1]; read c[i+1] from array
  do
    local g=lcg(seed({SD2_}))
    local iv={IVD_}
    for i=1,blen do
      local nxt; if i<blen then nxt=b[i+1] else nxt=iv end
      b[i]=(b[i]-g()-nxt)%256
    end
  end
  -- undo L3 (sub C -> add back)
  do local g=lcg(seed({SC_})) for i=1,blen do b[i]=(b[i]+g())%256 end end
  -- undo L2 (forward CBC): x1[i] = c[i]-ksB[i]-c[i-1]; use saved prev ciphertext
  do
    local g=lcg(seed({SB_}))
    local prev={IVB_}
    for i=1,blen do
      local cur=b[i]
      b[i]=(cur-g()-prev)%256
      prev=cur
    end
  end
  -- undo L1 (add A -> sub)
  do local g=lcg(seed({SA_})) for i=1,blen do b[i]=(b[i]-g())%256 end end
  -- bytes -> string in blocks
  local sc=string.char
  local parts={}
  local buf={}
  local bn=0
  for i=1,blen do
    bn=bn+1 buf[bn]=b[i]
    if bn==2048 then parts[#parts+1]=sc(table.unpack(buf,1,bn)) bn=0 end
  end
  if bn>0 then parts[#parts+1]=sc(table.unpack(buf,1,bn)) end
  local src=table.concat(parts)
  local ld=loadstring or load
  local fn,err=ld(src)
  if not fn then error(err) end
  return fn()
end
"""


def build_stage3(seeds, ivb, ivd, alphabet):
    s = STAGE3
    repl = {
        "A_": LCG_A, "C_": LCG_C, "M_": MASK32, "HM_": HMOD,
        "ALPHA_": '"' + alphabet + '"',
        "SA_": seeds["A"], "SB_": seeds["B"], "SC_": seeds["C"],
        "SD2_": seeds["D"], "SE_": seeds["E"], "SD_": seeds["S"],
        "IVB_": ivb, "IVD_": ivd,
    }
    for k, v in repl.items():
        s = s.replace("{" + k + "}", str(v))
    return s


# --------------------------------------------------------------------------- #
# A tiny self-contained transform used to bury stages 2 and 3: add-keystream + #
# substitution-hex, with its own alphabet + seed. Decoder is emitted inline.   #
# --------------------------------------------------------------------------- #
def mini_encode(src_text, seed, alphabet):
    data = enc_add(src_text.encode("utf-8"), seed)
    return serialize(data, alphabet)


MINI_LOADER = r"""(function(_b,_s,_al)
  local _a,_c,_m={A_},{C_},{M_}
  local _g=(function(x) x=x%_m return function() x=(x*_a+_c)%_m return (math.floor(x/65536))%256 end end)(_s)
  local _iv={} for _i=1,16 do _iv[string.byte(_al,_i)]=_i-1 end
  local _sb=string.byte
  local _n=math.floor(#_b/2)
  local _t={}
  for _i=1,_n do _t[_i]=(_iv[_sb(_b,2*_i-1)]*16+_iv[_sb(_b,2*_i)]-_g())%256 end
  local _sc=string.char local _p={} local _bf={} local _k=0
  for _i=1,_n do _k=_k+1 _bf[_k]=_t[_i] if _k==2048 then _p[#_p+1]=_sc(table.unpack(_bf,1,_k)) _k=0 end end
  if _k>0 then _p[#_p+1]=_sc(table.unpack(_bf,1,_k)) end
  return (loadstring or load)(table.concat(_p))
end)"""


def mini_loader_lua():
    s = MINI_LOADER
    s = s.replace("{A_}", str(LCG_A)).replace("{C_}", str(LCG_C)).replace("{M_}", str(MASK32))
    return s


def build_file(source_bytes, seed=None):
    rng = random.Random(seed)

    def rs():
        return rng.randrange(1, MASK32)

    # effective seeds used for encoding (the ones the decoder must reconstruct)
    eff = {k: rs() for k in ("A", "B", "C", "D", "E", "S")}
    ivb = rng.randrange(0, 256)
    ivd = rng.randrange(0, 256)

    def shuffled_hex():
        a = list("0123456789abcdef")
        rng.shuffle(a)
        return "".join(a)

    alphabet = shuffled_hex()

    # ---- payload pipeline ----
    d = enc_add(source_bytes, eff["A"])
    d = enc_fwd_cbc(d, eff["B"], ivb)
    d = enc_sub(d, eff["C"])
    d = enc_bwd_cbc(d, eff["D"], ivd)
    d = enc_add(d, eff["E"])
    text = serialize(d, alphabet)
    chunks = chunk_shuffle(text, 8192, eff["S"])
    stored = "".join(chunks)
    H = texthash(stored)

    # anti-tamper: store base = eff - H, decoder adds H back
    base = {k: (v - H) % MASK32 for k, v in eff.items()}

    # ---- stage 3 (real decoder), parameterised with the *base* seeds ----
    stage3 = build_stage3(base, ivb, ivd, alphabet)

    # ---- stage 2: decode+run stage3, then call it with D ----
    a2 = shuffled_hex()
    s2seed = rs()
    blob3 = mini_encode(stage3, s2seed, a2)
    stage2 = (
        "return function(D)\n"
        "  local f3 = " + mini_loader_lua() + "(" + lua_str(blob3) + "," + str(s2seed) + ",\"" + a2 + "\")\n"
        "  return f3()(D)\n"
        "end\n"
    )

    # ---- stage 1 (visible): decode+run stage2, pass the data table ----
    a1 = shuffled_hex()
    s1seed = rs()
    blob2 = mini_encode(stage2, s1seed, a1)

    out = []
    out.append("--!nocheck")
    out.append("-- Mahiro Hub protected build. Do not edit. Decodes and runs at load time.")
    out.append("local _D={k={")
    for ch in chunks:
        out.append(lua_str(ch) + ",")
    out.append("}}")
    out.append("local _f2 = " + mini_loader_lua() + "(" + lua_str(blob2) + "," + str(s1seed) + ",\"" + a1 + "\")")
    out.append("return _f2()(_D)")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="Mahiro Hub multi-layer obfuscator (v2)")
    ap.add_argument("input")
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()
    with open(args.input, "rb") as f:
        src = f.read()
    result = build_file(src, seed=args.seed)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(result)
    print("input  bytes:", len(src))
    print("output bytes:", len(result.encode("utf-8")))
    print("wrote:", args.output)


if __name__ == "__main__":
    main()
