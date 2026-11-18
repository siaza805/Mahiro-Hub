#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mahiro Hub multi-layer obfuscator.

Takes a plaintext Luau source file and emits a heavily obfuscated, still-runnable
single file. The payload is NEVER parsed; it is treated as opaque bytes, encoded
through several reversible layers, and reconstructed + loadstring()'d at runtime.

Pipeline (encode order; runtime reverses it):
  L1  add  keystream  (LCG A)        byte-wise, position dependent
  L2  sub  keystream  (LCG B)        reversed direction so layers can't collapse
  L3  add-chain + keystream (LCG C)  CBC-like feedback: each byte depends on all
                                     previous ones (diffusion)
  SER bytes -> 2 chars via a shuffled hex alphabet (substitution, not plain hex)
  CHK split into chunks, Fisher-Yates shuffle chunk order (LCG D)

Everything uses integer arithmetic only (no bit32, no native bitwise operators),
so the exact same decoder runs on Roblox/Luau and on stock Lua 5.1-5.4. That also
lets the build verify the output end to end before publishing.

Two stages:
  * The big ciphertext chunk table + seeds live in the top file (DATA).
  * The actual decode logic (STAGE2) is itself encoded into a small BOOT blob, so
    reading the top file tells you nothing about how to decode without first
    peeling BOOT. BOOT is decoded by a deliberately noisy inline bootstrap.
"""

import os
import sys
import random
import argparse

MASK32 = 0x100000000  # 2**32  (LCG modulus; A*(m-1)+C < 2**53 so exact in doubles)
LCG_A = 1664525
LCG_C = 1013904223


class LCG:
    """Linear congruential keystream. Must match the Lua implementation exactly."""

    def __init__(self, seed):
        self.s = seed % MASK32

    def nextbyte(self):
        self.s = (self.s * LCG_A + LCG_C) % MASK32
        return (self.s // 65536) % 256  # middle bits 16..23

    def nextint(self):
        self.s = (self.s * LCG_A + LCG_C) % MASK32
        return self.s


def layer1_encode(data, seed):
    g = LCG(seed)
    return bytes((b + g.nextbyte()) % 256 for b in data)


def layer2_encode(data, seed):
    g = LCG(seed)
    return bytes((b - g.nextbyte()) % 256 for b in data)


def layer3_encode(data, seed, iv):
    g = LCG(seed)
    out = bytearray(len(data))
    prev = iv
    for i, b in enumerate(data):
        c = (b + g.nextbyte() + prev) % 256
        out[i] = c
        prev = c
    return bytes(out)


def serialize(data, alphabet):
    # byte -> two symbols from a 16-char shuffled alphabet
    out = []
    for b in data:
        out.append(alphabet[b >> 4])
        out.append(alphabet[b & 0x0F])
    return "".join(out)


def fisher_yates_perm(n, seed):
    """Return perm[] where perm[i] is the original index now sitting at position i.
    Identical algorithm is re-run in Lua to invert the shuffle."""
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
    # out[i] = chunks[perm[i]]  -> decoder puts out[i] back at perm[i]
    out = [chunks[perm[i]] for i in range(n)]
    return out


def lua_str(s):
    """Emit a Lua long-bracket string, choosing a level that can't collide."""
    level = 0
    while ("]" + "=" * level + "]") in s or ("[" + "=" * level + "[") in s:
        level += 1
    eq = "=" * level
    return "[" + eq + "[" + s + "]" + eq + "]"


# --------------------------------------------------------------------------- #
# Stage 2 decoder (runs the reverse pipeline). Written as a function of DATA.  #
# Plain, portable Lua; gets encoded into BOOT so it is not visible up front.   #
# --------------------------------------------------------------------------- #
STAGE2_TEMPLATE = r"""
return function(D)
  local A,C,M = {A_},{C_},{M_}
  local function lcg(seed)
    local s=seed%M
    return function()
      s=(s*A+C)%M
      return s
    end
  end
  local function kbyte(gen) return (math.floor(gen()/65536))%256 end
  -- rebuild symbol -> nibble map
  local ALPHA={ALPHA_}
  local inv={}
  for i=1,16 do inv[string.byte(ALPHA,i)]=i-1 end
  -- 1) undo chunk shuffle
  local chunks=D.k
  local n=#chunks
  local a={}
  for i=1,n do a[i]=i-1 end
  do
    local g=lcg({SEED_D})
    local i=n
    while i>=2 do
      local j=(g()%i)+1
      a[i],a[j]=a[j],a[i]
      i=i-1
    end
  end
  local ordered={}
  for i=1,n do ordered[a[i]+1]=chunks[i] end
  local text=table.concat(ordered)
  -- 2) symbols -> bytes
  local blen=math.floor(#text/2)
  local bytes={}
  local sb=string.byte
  for i=1,blen do
    local hi=inv[sb(text,2*i-1)]
    local lo=inv[sb(text,2*i)]
    bytes[i]=hi*16+lo
  end
  -- 3) undo L3 (add-chain + keystream C)
  do
    local g=lcg({SEED_C})
    local prev={IV_}
    for i=1,blen do
      local c=bytes[i]
      bytes[i]=(c-kbyte(g)-prev)%256
      prev=c
    end
  end
  -- 4) undo L2 (we subtracted, so add back)
  do
    local g=lcg({SEED_B})
    for i=1,blen do bytes[i]=(bytes[i]+kbyte(g))%256 end
  end
  -- 5) undo L1 (we added, so subtract)
  do
    local g=lcg({SEED_A})
    for i=1,blen do bytes[i]=(bytes[i]-kbyte(g))%256 end
  end
  -- 6) bytes -> string, in blocks to avoid huge arg lists
  local sc=string.char
  local parts={}
  local buf={}
  local bn=0
  for i=1,blen do
    bn=bn+1
    buf[bn]=bytes[i]
    if bn==2048 then
      parts[#parts+1]=sc(table.unpack(buf,1,bn))
      bn=0
    end
  end
  if bn>0 then parts[#parts+1]=sc(table.unpack(buf,1,bn)) end
  local src=table.concat(parts)
  local ld=loadstring or load
  local fn,err=ld(src)
  if not fn then error(err) end
  return fn()
end
"""


def build_stage2(seeds, iv, alphabet):
    s = STAGE2_TEMPLATE
    s = s.replace("{A_}", str(LCG_A))
    s = s.replace("{C_}", str(LCG_C))
    s = s.replace("{M_}", str(MASK32))
    s = s.replace("{SEED_A}", str(seeds["A"]))
    s = s.replace("{SEED_B}", str(seeds["B"]))
    s = s.replace("{SEED_C}", str(seeds["C"]))
    s = s.replace("{SEED_D}", str(seeds["D"]))
    s = s.replace("{IV_}", str(iv))
    s = s.replace("{ALPHA_}", '"' + alphabet + '"')
    return s


# --------------------------------------------------------------------------- #
# Stage 1 bootstrap: decode BOOT (a plain add-keystream + shuffled-hex blob of  #
# the stage-2 source) and run it with the DATA table. Deliberately cryptic.     #
# --------------------------------------------------------------------------- #
def encode_boot(stage2_src, seed, alphabet):
    """Simple, self-contained transform for the small stage-2 blob."""
    data = stage2_src.encode("utf-8")
    enc = layer1_encode(data, seed)      # reuse add-keystream
    return serialize(enc, alphabet)


BOOT_LOADER_TEMPLATE = r"""do
  local _a,_c,_m={A_},{C_},{M_}
  local function _g(_s)
    _s=_s%_m
    return function() _s=(_s*_a+_c)%_m return (math.floor(_s/65536))%256 end
  end
  local _al={ALPHA_}
  local _iv={}
  for _i=1,16 do _iv[string.byte(_al,_i)]=_i-1 end
  local _t={BOOT_}
  local _sb=string.byte
  local _n=math.floor(#_t/2)
  local _b={}
  local _k=_g({BOOTSEED_})
  for _i=1,_n do
    local _hi=_iv[_sb(_t,2*_i-1)]
    local _lo=_iv[_sb(_t,2*_i)]
    local _v=(_hi*16+_lo-((math.floor((function() return nil end) and 0 or 0))) )
    _b[_i]=(_v-_k())%256
  end
  local _sc=string.char
  local _ps={}
  local _bf={}
  local _bn=0
  for _i=1,_n do
    _bn=_bn+1
    _bf[_bn]=_b[_i]
    if _bn==2048 then _ps[#_ps+1]=_sc(table.unpack(_bf,1,_bn)) _bn=0 end
  end
  if _bn>0 then _ps[#_ps+1]=_sc(table.unpack(_bf,1,_bn)) end
  local _src=table.concat(_ps)
  local _ld=loadstring or load
  local _f=assert(_ld(_src))()
  return _f(_D)
end
"""


def build_file(source_bytes, seed=None):
    rng = random.Random(seed)
    seeds = {
        "A": rng.randrange(1, MASK32),
        "B": rng.randrange(1, MASK32),
        "C": rng.randrange(1, MASK32),
        "D": rng.randrange(1, MASK32),
    }
    iv = rng.randrange(0, 256)
    boot_seed = rng.randrange(1, MASK32)

    hexsyms = list("0123456789abcdef")
    rng.shuffle(hexsyms)
    alphabet = "".join(hexsyms)

    boot_syms = list("0123456789abcdef")
    rng.shuffle(boot_syms)
    boot_alphabet = "".join(boot_syms)

    # ---- payload pipeline ----
    d = layer1_encode(source_bytes, seeds["A"])
    d = layer2_encode(d, seeds["B"])
    d = layer3_encode(d, seeds["C"], iv)
    text = serialize(d, alphabet)
    chunk_size = 8192
    chunks = chunk_shuffle(text, chunk_size, seeds["D"])

    # ---- stage 2 (decode logic), encoded into BOOT ----
    stage2 = build_stage2(seeds, iv, alphabet)
    boot_blob = encode_boot(stage2, boot_seed, boot_alphabet)

    # ---- assemble file ----
    out = []
    out.append("--!nocheck")
    out.append("-- Mahiro Hub protected build. Do not edit.")
    out.append("-- Encoded distribution; decodes and runs at load time.")
    # DATA table
    out.append("local _D={k={")
    for ch in chunks:
        out.append(lua_str(ch) + ",")
    out.append("}}")
    # boot alphabet + blob are embedded inside the loader template
    loader = BOOT_LOADER_TEMPLATE
    loader = loader.replace("{A_}", str(LCG_A))
    loader = loader.replace("{C_}", str(LCG_C))
    loader = loader.replace("{M_}", str(MASK32))
    loader = loader.replace("{ALPHA_}", '"' + boot_alphabet + '"')
    loader = loader.replace("{BOOT_}", lua_str(boot_blob))
    loader = loader.replace("{BOOTSEED_}", str(boot_seed))
    out.append(loader)
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="Mahiro Hub multi-layer obfuscator")
    ap.add_argument("input", help="plaintext Luau source file")
    ap.add_argument("-o", "--output", required=True, help="output obfuscated file")
    ap.add_argument("--seed", type=int, default=None,
                    help="deterministic RNG seed (default: random each run)")
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
