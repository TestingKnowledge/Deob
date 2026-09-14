#!/usr/bin/env python3
"""
Lua Obfuscator / Deobfuscator — Discord bot.

Commands
--------
.obfuscate    (aliases: .obf, .protect)      upload a .lua/.txt file with this
                                             command to receive the obfuscated
                                             file back as a .lua attachment
.deobfuscate  (aliases: .deobf, .decode, .unobfuscate)
                                             upload an obfuscated .lua/.txt
                                             file to receive BOTH:
                                               - the decoded payload (.lua)
                                               - the full 14-section
                                                 reverse-engineering report
                                                 (.txt)
.help, .ping, .stats

The obfuscation engine implements the WeAreDevs-style layered scheme and the
deobfuscator implements the complete reverse-engineering methodology from the
master prompt (critical-path extraction, round-trip verification, honest
[UNKNOWN] reporting, 14-section report).
"""
from __future__ import annotations

import asyncio
import io
import json
import os
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import discord
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv


# ==========================================================================
# LUA OBFUSCATOR ENGINE (inlined from obfuscator/engine.py)
# ==========================================================================

import random
import re
from dataclasses import dataclass, field

# ==========================================================================
# Lua string literal extraction / re-emission
# ==========================================================================

_ESCAPES = {
    'a': '\a', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r',
    't': '\t', 'v': '\v', '\\': '\\', '"': '"', "'": "'",
}


def decode_lua_string(raw_body: str) -> bytes:
    """Decode a Lua short-string body (text between the quotes)."""
    out = bytearray()
    i, n = 0, len(raw_body)
    while i < n:
        ch = raw_body[i]
        if ch == '\\':
            i += 1
            if i >= n:
                break
            c = raw_body[i]
            if c in _ESCAPES:
                out.append(ord(_ESCAPES[c]))
                i += 1
            elif c == 'x':
                hexs = raw_body[i + 1:i + 3]
                try:
                    out.append(int(hexs, 16))
                except ValueError:
                    out.append(ord('x'))
                i += 3
            elif c.isdigit():
                dec = c
                i += 1
                while i < n and raw_body[i].isdigit() and len(dec) < 3:
                    dec += raw_body[i]
                    i += 1
                out.append(int(dec) & 0xFF)
            elif c == 'z':
                i += 1
                while i < n and raw_body[i] in ' \t\r\n':
                    i += 1
            else:
                out.append(ord(c))
                i += 1
        else:
            out.append(ord(ch))
            i += 1
    return bytes(out)


def encode_lua_string(data: bytes) -> str:
    """Encode raw bytes as a printable double-quoted Lua literal."""
    out = []
    for b in data:
        if b == 0x22:
            out.append('\\"')
        elif b == 0x5C:
            out.append('\\\\')
        elif b == 0x0A:
            out.append('\\n')
        elif 0x20 <= b < 0x7F:
            out.append(chr(b))
        else:
            out.append('\\%d' % b)
    return '"' + ''.join(out) + '"'


def extract_string_literals(source: str):
    """
    Return [(start, end, raw_bytes, quote)] for every string literal.
    Long-bracket strings are captured verbatim; comments are skipped.
    """
    lits = []
    i, n = 0, len(source)
    while i < n:
        c = source[i]
        if c == '-' and source[i + 1:i + 2] == '-':
            if source[i + 2:i + 4] == '[[':
                close = source.find(']]', i + 2)
                i = (close + 2) if close != -1 else n
            else:
                nl = source.find('\n', i)
                i = (nl + 1) if nl != -1 else n
            continue
        if c in ('"', "'"):
            j = i + 1
            body = []
            while j < n:
                cj = source[j]
                if cj == '\\':
                    body.append(source[j:j + 2])
                    j += 2
                elif cj == c:
                    break
                else:
                    body.append(cj)
                    j += 1
            if j < n and source[j] == c:
                lits.append((i, j + 1, decode_lua_string(''.join(body)), c))
                i = j + 1
            else:
                i += 1
            continue
        if c == '[' and source[i + 1:i + 2] == '[':
            close = source.find(']]', i + 2)
            if close != -1:
                body = source[i + 2:close]
                lits.append((i, close + 2, body.encode('latin-1', 'replace'), 'long'))
                i = close + 2
                continue
            i += 1
            continue
        i += 1
    return lits


# ==========================================================================
# Custom alphabets + exact base-85 / base-64 codecs (Ascii85 conventions)
# ==========================================================================

B85_CHARS = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"
B64_CHARS = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/"

B85_POWERS = (52200625, 614125, 7225, 85, 1)      # 85^4 .. 85^0
B64_POWERS = (262144, 4096, 64, 1)                # 64^3 .. 64^0


def shuffled_alphabet(chars: bytes, rng: random.Random) -> bytes:
    lst = list(chars)
    rng.shuffle(lst)
    return bytes(lst)


def b85_encode(data: bytes, alphabet: bytes) -> str:
    """4-byte groups -> 5 digits; trailing r-byte group -> r+1 digits."""
    out = []
    for k in range(0, len(data), 4):
        chunk = data[k:k + 4]
        v = int.from_bytes(chunk + b'\x00' * (4 - len(chunk)), 'big')
        digits = [alphabet[v // p % 85] for p in B85_POWERS]
        out.extend(digits[:len(chunk) + 1])
    return ''.join(chr(c) for c in out)


def b85_decode(text: str, alphabet: bytes) -> bytes:
    """Inverse of b85_encode (short groups padded with MAX digit)."""
    out = bytearray()
    pos, n = 0, len(text)
    max_digit = chr(alphabet[84])
    while pos < n:
        block = text[pos:pos + 5]
        m = len(block)
        if m < 5:
            block = block + max_digit * (5 - m)
        v = 0
        for ch in block:
            v = v * 85 + alphabet.index(ord(ch))
        quad = v.to_bytes(4, 'big')
        take = 4 if m == 5 else m - 1
        out.extend(quad[:take])
        pos += 5
    return bytes(out)


def b64_encode(data: bytes, alphabet: bytes) -> str:
    """3-byte groups -> 4 digits; trailing r-byte group -> r+1 digits."""
    out = []
    for k in range(0, len(data), 3):
        chunk = data[k:k + 3]
        v = int.from_bytes(chunk + b'\x00' * (3 - len(chunk)), 'big')
        digits = [alphabet[v // p % 64] for p in B64_POWERS]
        out.extend(digits[:len(chunk) + 1])
    return ''.join(chr(c) for c in out)


def b64_decode(text: str, alphabet: bytes) -> bytes:
    """Inverse of b64_encode (short groups padded with MAX digit)."""
    out = bytearray()
    pos, n = 0, len(text)
    max_digit = chr(alphabet[63])
    while pos < n:
        block = text[pos:pos + 4]
        m = len(block)
        if m < 4:
            block = block + max_digit * (4 - m)
        v = 0
        for ch in block:
            v = v * 64 + alphabet.index(ord(ch))
        tri = v.to_bytes(3, 'big')
        take = 3 if m == 4 else m - 1
        out.extend(tri[:take])
        pos += 4
    return bytes(out)


# ==========================================================================
# Arithmetic camouflage
# ==========================================================================

class Camo:
    """Emits camouflaged constant expressions (a+b / a-b / a%b)."""

    def __init__(self, rng: random.Random):
        self.rng = rng

    def const(self, value: int) -> str:
        """Always parenthesised, so the expression is precedence-safe in
        any context (e.g. `V*(123456+654321)` == `V*16452`).
        NOTE: the modulo form is only emitted when 0 <= value < 1000,
        because `(b*k+v)%b == v` requires 0 <= v < b (Lua's % always
        returns a non-negative result for positive divisors)."""
        value = int(value)
        if value == 0:
            a = self.rng.randrange(100000, 900000)
            return "(%d-%d)" % (a, a)
        r = self.rng.random()
        if r < 0.4:
            b = self.rng.randrange(100000, 900000) * self.rng.choice([1, -1])
            return "(%d+%d)" % (value - b, b)
        if r < 0.8:
            b = self.rng.randrange(100000, 900000)
            return "(%d-%d)" % (value + b, b)
        if 0 < value < 1000:
            b = self.rng.randrange(1000, 99999)
            k = self.rng.randrange(2, 500)
            return "(%d%%%d)" % (b * k + value, b)
        # large / negative value: fall back to the always-exact sum form
        b = self.rng.randrange(100000, 900000) * self.rng.choice([1, -1])
        return "(%d+%d)" % (value - b, b)


# ==========================================================================
# Payload analysis (pure-call detection for VM virtualization)
# ==========================================================================

@dataclass
class CallStmt:
    func: str
    args: list                                  # ('str', bytes) | ('num', str)


@dataclass
class VMProgram:
    calls: list = field(default_factory=list)


_CALL_RE = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*(.*?)\s*\)\s*;?\s*$', re.S)
_NUM_RE = re.compile(r'^-?\d+(\.\d+)?([eE][+-]?\d+)?$')
KEYWORDS = {'local', 'return', 'if', 'for', 'while', 'function', 'end',
            'do', 'repeat', 'until', 'then', 'else', 'elseif', 'and', 'or',
            'not', 'in', 'break', 'goto'}


def split_top_args(argstr: str):
    """Split top-level comma-separated Lua expressions."""
    if not argstr.strip():
        return []
    parts, cur, depth, in_str = [], [], 0, None
    i = 0
    while i < len(argstr):
        c = argstr[i]
        if in_str:
            if c == '\\':
                cur.append(argstr[i:i + 2])
                i += 2
                continue
            if c == in_str:
                in_str = None
            cur.append(c)
        elif c in ('"', "'"):
            in_str = c
            cur.append(c)
        elif c in '([{':
            depth += 1
            cur.append(c)
        elif c in ')]}':
            depth -= 1
            cur.append(c)
        elif c == ',' and depth == 0:
            parts.append(''.join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    if cur:
        parts.append(''.join(cur))
    return parts


def strip_comments(source: str) -> str:
    s = re.sub(r'--\[\[.*?\]\]', '', source, flags=re.S)
    s = re.sub(r'--[^\n]*', '', s)
    return s


def parse_top_level_calls(source: str) -> VMProgram:
    """Extract simple top-level global calls with literal-only arguments."""
    prog = VMProgram()
    for raw in re.split(r'[;\n]', strip_comments(source)):
        stmt = raw.strip()
        if not stmt:
            continue
        m = _CALL_RE.match(stmt)
        if not m:
            continue
        func = m.group(1)
        if func in KEYWORDS:
            continue
        args, ok = [], True
        for part in split_top_args(m.group(2)):
            p = part.strip()
            if ((p.startswith('"') or p.startswith("'"))
                    and (p.endswith('"') or p.endswith("'")) and len(p) >= 2):
                args.append(('str', decode_lua_string(p[1:-1])))
            elif _NUM_RE.match(p):
                args.append(('num', p))
            else:
                ok = False
                break
        if ok:
            prog.calls.append(CallStmt(func=func, args=args))
    return prog


def is_pure_call_program(source: str, prog: VMProgram) -> bool:
    """True when the source consists ONLY of the extracted simple calls."""
    stmts = [s.strip() for s in re.split(r'[;\n]', strip_comments(source)) if s.strip()]
    if len(stmts) != len(prog.calls) or not prog.calls:
        return False
    for stmt, call in zip(stmts, prog.calls):
        m = _CALL_RE.match(stmt)
        if not m or m.group(1) != call.func:
            return False
    return True


# ==========================================================================
# Permutation loop (exact simulation of the emitted Lua)
# ==========================================================================

def simulate_permutation(n: int, iterations: int):
    """
    Simulate:
        local a,b = 1,2
        for i = 0, T-1 do
          U[a],U[b] = U[b],U[a]
          if b == n then a,b = 1,2 else a,b = a+1,b+1 end
        end
    Returns final[i-1] = original position now at final position i.
    """
    arr = list(range(1, n + 1))
    a, b = 1, 2
    for _ in range(iterations):
        arr[a - 1], arr[b - 1] = arr[b - 1], arr[a - 1]
        if b == n:
            a, b = 1, 2
        else:
            a, b = a + 1, b + 1
    return arr


# ==========================================================================
# Obfuscation engine
# ==========================================================================

DECOY_STRINGS = [
    b"Tamper Detected!",
    b"This script is protected",
    b"Internal error 0x8F",
    b"Loading modules...",
    b"Verifying integrity",
    b"Anti-cheat initialised",
]

PARAMS = "q,Q,l,L,T,gM,sM,np,un,fe,mF,E"
PRIMS = ("string.char,string.sub,table.concat,string.len,type,"
         "getmetatable,setmetatable,newproxy,"
         "(unpack or table.unpack),"
         "(getfenv or function() return _ENV end),math.floor,_G")


class ObfuscationEngine:
    def __init__(self, seed: int | None = None):
        self.rng = random.Random(seed)
        self.camo = Camo(self.rng)

    # ------------------------------------------------------------------

    def obfuscate(self, source: str, banner: str = "v1.0.1") -> str:
        rng, camo = self.rng, self.camo
        self.b85 = shuffled_alphabet(B85_CHARS, rng)
        self.b64 = shuffled_alphabet(B64_CHARS, rng)

        lits = extract_string_literals(source)
        unique, seen = [], {}
        for (_s, _e, data, _q) in lits:
            if data not in seen:
                seen[data] = True
                unique.append(data)

        # ---- pool: unique strings + decoys, then shuffle ----
        plan, entries = [], []
        for data in unique:
            if len(data) >= 6:
                entries.append('l' + b85_encode(data, self.b85))
                plan.append(('l', data))
            elif len(data) > 0:
                entries.append('s' + b64_encode(data, self.b64))
                plan.append(('s', data))
            else:
                entries.append('s')
                plan.append(('s', b''))
        for decoy in rng.sample(DECOY_STRINGS, 3):
            entries.append('?' + decoy.decode('latin-1'))
            plan.append(('?', decoy))
        order = list(range(len(entries)))
        rng.shuffle(order)
        entries = [entries[i] for i in order]
        plan = [plan[i] for i in order]
        n = len(entries)

        # ---- permutation ----
        passes = rng.randrange(1, 8) if n > 1 else 0
        iterations = passes * (n - 1) if n > 1 else 0
        final_map = (simulate_permutation(n, iterations) if iterations
                     else list(range(1, n + 1)))
        final_entries = [entries[final_map[i - 1] - 1] for i in range(1, n + 1)]
        final_plan = [plan[final_map[i - 1] - 1] for i in range(1, n + 1)]

        final_index = {}
        for idx, (kind, data) in enumerate(final_plan, start=1):
            if kind != '?':
                final_index[data] = idx

        big = rng.randrange(16000, 20000)
        prog = parse_top_level_calls(source)
        virtualize = is_pure_call_program(source, prog)

        return self._emit(
            lits=lits, final_index=final_index, pool_entries=entries,
            n=n, iterations=iterations, big=big,
            prog=prog if virtualize else None,
            source=source, banner=banner,
        )

    # ------------------------------------------------------------------

    def _emit(self, *, lits, final_index, pool_entries, n, iterations,
              big, prog, source, banner):
        camo = self.camo
        header = f"--[[ {banner} https://wearedevs.net/obfuscator ]]\n"

        o_lit = ','.join(encode_lua_string(bytes([c])) for c in self.b85)
        w_lit = ','.join(encode_lua_string(bytes([c])) for c in self.b64)

        if iterations:
            perm = (
                f"local a,b={camo.const(1)},{camo.const(2)}\n"
                f"for i={camo.const(0)},{camo.const(iterations - 1)} do\n"
                f"U[a],U[b]=U[b],U[a]\n"
                f"if b=={camo.const(n)} then a,b={camo.const(1)},{camo.const(2)} "
                f"else a,b=a+{camo.const(1)},b+{camo.const(1)} end\n"
                f"end\n"
            )
        else:
            perm = ""

        s_def = f"local function S(x)\n return U[x+({camo.const(big)})]\nend\n"
        k_def = self._emit_decoder()

        if prog is not None:
            body = self._emit_vm(prog, final_index, n, big)
        else:
            body = self._emit_rewritten_body(source, lits, final_index, big)

        pool_args = ','.join(encode_lua_string(e.encode('latin-1'))
                             for e in pool_entries)

        return (
            f"{header}"
            f"return(function({PARAMS},...)\n"
            f"local U={{...}}\n"
            f"{perm}"
            f"local o={{{o_lit}}}\n"
            f"local w={{{w_lit}}}\n"
            f"local O,W={{}},{{}}\n"
            f"for i=1,#o do O[o[i]]=i end\n"
            f"for i=1,#w do W[w[i]]=i end\n"
            f"{s_def}"
            f"{k_def}"
            f"{body}"
            f"end)({PRIMS},{pool_args})\n"
        )

    # ------------------------------------------------------------------

    def _emit_decoder(self) -> str:
        """
        Custom string decoder K(v):
          'l' branch -> custom base-85 (5 digits <-> 4 bytes)
          's' branch -> custom base-64 (4 digits <-> 3 bytes)
          '?' branch -> decoy plaintext passthrough
        Short trailing groups are padded with MAX digits, exactly like
        the Python codecs above.
        """
        c = self.camo.const
        return f"""local function K(v)
local t=Q(v,{c(1)},{c(1)})
if t=='l' then
local p=Q(v,{c(2)})
local nd=#p%{c(5)}
local nf=(#p-nd)/{c(5)}
local B,V,nn,ps={{}},{c(0)},{c(0)},{c(1)}
for g={c(1)},nf do
V={c(0)}
for j={c(0)},{c(4)} do V=V*{c(85)}+O[Q(p,ps+j,ps+j)]-{c(1)} end
B[nn+{c(1)}]=q(mF(V/{c(16777216)})%{c(256)})
B[nn+{c(2)}]=q(mF(V/{c(65536)})%{c(256)})
B[nn+{c(3)}]=q(mF(V/{c(256)})%{c(256)})
B[nn+{c(4)}]=q(V%{c(256)})
nn=nn+{c(4)} ps=ps+{c(5)}
end
if nd>{c(1)} then
V={c(0)}
for j={c(0)},nd-{c(1)} do V=V*{c(85)}+O[Q(p,ps+j,ps+j)]-{c(1)} end
for j=nd,{c(4)} do V=V*{c(85)}+{c(84)} end
local T=q(mF(V/{c(16777216)})%{c(256)},mF(V/{c(65536)})%{c(256)},mF(V/{c(256)})%{c(256)},V%{c(256)})
for j={c(1)},nd-{c(1)} do B[nn+j]=Q(T,j,j) end
end
return l(B)
elseif t=='s' then
local p=Q(v,{c(2)})
if #p=={c(0)} then return '' end
local nd=#p%{c(4)}
local nf=(#p-nd)/{c(4)}
local B,V,nn,ps={{}},{c(0)},{c(0)},{c(1)}
for g={c(1)},nf do
V={c(0)}
for j={c(0)},{c(3)} do V=V*{c(64)}+W[Q(p,ps+j,ps+j)]-{c(1)} end
B[nn+{c(1)}]=q(mF(V/{c(65536)})%{c(256)})
B[nn+{c(2)}]=q(mF(V/{c(256)})%{c(256)})
B[nn+{c(3)}]=q(V%{c(256)})
nn=nn+{c(3)} ps=ps+{c(4)}
end
if nd>{c(1)} then
V={c(0)}
for j={c(0)},nd-{c(1)} do V=V*{c(64)}+W[Q(p,ps+j,ps+j)]-{c(1)} end
for j=nd,{c(3)} do V=V*{c(64)}+{c(63)} end
local T=q(mF(V/{c(65536)})%{c(256)},mF(V/{c(256)})%{c(256)},V%{c(256)})
for j={c(1)},nd-{c(1)} do B[nn+j]=Q(T,j,j) end
end
return l(B)
else
return Q(v,{c(2)})
end
end
"""

    # ------------------------------------------------------------------

    def _emit_rewritten_body(self, source, lits, final_index, big) -> str:
        """General payload: strings -> S(idx), integers -> camouflaged."""
        camo = self.camo
        out, last = [], 0
        for (s, e, data, q) in lits:
            if q == 'long':
                continue
            out.append(source[last:s])
            idx = final_index.get(data)
            if idx is None:
                out.append(source[s:e])
            else:
                out.append(f"K(S({camo.const(idx - big)}))")
            last = e
        out.append(source[last:])
        body = ''.join(out)
        body = _camo_numbers(body, camo)
        return body + "\n"

    # ------------------------------------------------------------------

    def _emit_vm(self, prog: VMProgram, final_index, pool_len, big) -> str:
        """Flattened mini-VM for pure-call payloads."""
        camo = self.camo
        rng = self.rng

        # ---------------- allocate virtual registers ----------------
        reg = 2
        const_reg, global_reg, argpack_reg = {}, {}, {}

        def const_key(kind, val):
            return ('s', val) if kind == 'str' else ('n', val)

        for call in prog.calls:
            for kind, val in call.args:
                key = const_key(kind, val)
                if key not in const_reg:
                    const_reg[key] = reg
                    reg += 1
        for fn in dict.fromkeys(c.func for c in prog.calls):
            global_reg[fn] = reg
            reg += 1
        for i in range(len(prog.calls)):
            argpack_reg[i] = reg
            reg += 1
        result_reg = reg
        reg += 1

        sid = rng.randrange(1000, 2000)
        step = lambda: rng.randrange(3, 9)

        states = []          # (id, [lua lines])
        links = {}           # id -> next id (None = terminal / L=nil)

        # --- init state ---
        s_init = sid
        sid += step()
        states.append((s_init, ["Z={}"]))

        # --- global resolution states (first-use order) ---
        glob_state = {}
        for fn in dict.fromkeys(c.func for c in prog.calls):
            glob_state[fn] = sid
            states.append((sid, [
                f"Z[{global_reg[fn]}]=E[{encode_lua_string(fn.encode())}]"
            ]))
            sid += step()

        # --- per-call states ---
        call_states = []
        for ci, call in enumerate(prog.calls):
            seq = []
            for kind, val in call.args:
                zr = const_reg[const_key(kind, val)]
                if kind == 'str':
                    idx = final_index[val]
                    states.append((sid, [
                        f"Z[{zr}]=K(S({camo.const(idx - big)}))"]))
                else:
                    states.append((sid, [
                        f"Z[{zr}]={camo.const(int(float(val)))}"]))
                seq.append(sid)
                sid += step()
            zr = argpack_reg[ci]
            items = ','.join(
                f"Z[{const_reg[const_key(k, v)]}]" for k, v in call.args)
            states.append((sid, [f"Z[{zr}]={{{items}}}"]))
            seq.append(sid)
            sid += step()
            gz = global_reg[call.func]
            states.append((sid, [
                f"Z[{result_reg}]=Z[{gz}](un(Z[{zr}]))"]))
            seq.append(sid)
            sid += step()
            call_states.append(seq)

        # --- return state ---
        s_ret = sid
        sid += step()
        states.append((s_ret, [f"I={{Z[{result_reg}]}}"]))

        # ---------------- link states ----------------
        fn_order = list(dict.fromkeys(c.func for c in prog.calls))
        links[s_init] = glob_state[fn_order[0]]
        for k, fn in enumerate(fn_order):
            if k + 1 < len(fn_order):
                links[glob_state[fn]] = glob_state[fn_order[k + 1]]
            else:
                links[glob_state[fn]] = call_states[0][0]
        for ci, seq in enumerate(call_states):
            for k in range(len(seq) - 1):
                links[seq[k]] = seq[k + 1]
            if ci + 1 < len(call_states):
                links[seq[-1]] = call_states[ci + 1][0]
            else:
                links[seq[-1]] = s_ret
        links[s_ret] = None                       # terminal: L = nil

        # ---------------- decoy unreachable states ----------------
        live = {i for (i, _l) in states}
        for _ in range(rng.randrange(4, 8)):
            while sid in live:
                sid += step()
            z = rng.randrange(2, result_reg + 1)
            states.append((sid, [
                f"Z[{z}]=K(S({camo.const(rng.randrange(1, pool_len + 1) - big)}))"]))
            links[sid] = None                     # unreachable
            sid += step()

        # ---------------- emit dispatcher ----------------
        states.sort(key=lambda t: t[0])
        lines = []
        lines.append(f"local Z,I,L={{}},nil,{camo.const(s_init)}")
        lines.append("while L do")
        first = True
        for (i, body) in states:
            kw = 'if' if first else 'elseif'
            first = False
            inner = '\n'.join(' ' + b for b in body)
            nxt = links[i]
            tail = f"L={camo.const(nxt)}" if nxt is not None else "L=nil"
            lines.append(f"{kw} L=={camo.const(i)} then\n{inner}\n{tail}")
        lines.append("end")
        lines.append("end")
        dispatch = '\n'.join(lines)

        # ---------------- function-wrapping layer (L6) ----------------
        return (
            "local function _w2()\n"
            f"{dispatch}\n"
            "return I\n"
            "end\n"
            "local function _w1()\n"
            "local I=_w2()\n"
            "return I\n"
            "end\n"
            "local I=_w1()\n"
            "return un(I)\n"
        )


# ==========================================================================
# Integer literal camouflage (general payloads)
# ==========================================================================

_NUM_TOKEN_RE = re.compile(r'(?<![\w.])0[xX][0-9a-fA-F]+|(?<![\w.])\d+(?![\w.])')


def _protected_regions(body: str):
    """Regions (strings/comments/long brackets) where digits must not be touched."""
    protected = []
    i, n = 0, len(body)
    while i < n:
        c = body[i]
        if c == '-' and body[i + 1:i + 2] == '-':
            if body[i + 2:i + 4] == '[[':
                close = body.find(']]', i + 2)
                j = (close + 2) if close != -1 else n
            else:
                nl = body.find('\n', i)
                j = (nl + 1) if nl != -1 else n
            protected.append((i, j))
            i = j
            continue
        if c in ('"', "'"):
            j = i + 1
            while j < n:
                if body[j] == '\\':
                    j += 2
                elif body[j] == c:
                    j += 1
                    break
                else:
                    j += 1
            protected.append((i, j))
            i = j
            continue
        if c == '[' and body[i + 1:i + 2] == '[':
            close = body.find(']]', i + 2)
            j = (close + 2) if close != -1 else n
            protected.append((i, j))
            i = j
            continue
        i += 1
    return protected


def _camo_numbers(body: str, camo: Camo) -> str:
    """
    Replace standalone integer literals with camouflaged parenthesised
    expressions.  S(...) spans emitted by the obfuscator are shielded so
    their internal camouflage is not nested again.
    """
    # shield S(...) calls
    shielded = []
    placeholder_map = {}

    def shield(m):
        token = f"\x00SH{len(shielded)}\x00"
        shielded.append((token, m.group(0)))
        return token

    body = re.sub(r'S\(\([^()]*\)\)', shield, body)  # S((expr)) spans

    protected = _protected_regions(body)

    def in_protected(p):
        return any(a <= p < b for (a, b) in protected)

    out, last = [], 0
    for m in _NUM_TOKEN_RE.finditer(body):
        if in_protected(m.start()):
            continue
        tok = m.group(0)
        try:
            val = int(tok, 0)
        except ValueError:
            continue
        out.append(body[last:m.start()])
        out.append(f"({camo.const(val)})")
        last = m.end()
    out.append(body[last:])
    body = ''.join(out)

    # restore shielded S() spans
    for token, original in shielded:
        body = body.replace(token, original)
    return body

# ==========================================================================
# LUA DEOBFUSCATOR ENGINE (inlined from deobfuscator/engine.py)
# ==========================================================================

# ==========================================================================
# Report structures
# ==========================================================================

@dataclass
class DecodedString:
    index: int
    encoded: str
    branch: str                       # 'l' | 's' | '?'
    decoded_bytes: bytes
    classification: str = 'UNKNOWN'   # EXECUTED / DECOY / ...
    used_by: list = field(default_factory=list)


@dataclass
class DeobfuscationResult:
    ok: bool = False
    method: str = ''
    source_length: int = 0
    banner: str | None = None
    iife_params: list = field(default_factory=list)
    primitives: dict = field(default_factory=dict)
    constants: list = field(default_factory=list)      # (expr, value, note)
    pool: list = field(default_factory=list)           # DecodedString
    permutation: str = ''
    b85_alphabet: bytes | None = None
    b64_alphabet: bytes | None = None
    vm_states: list = field(default_factory=list)      # (id, [lines], next)
    critical_path: list = field(default_factory=list)  # (id, desc)
    trace: list = field(default_factory=list)          # (step, text)
    payload: str = ''
    payload_status: str = 'NOT RECOVERED'
    confidence: str = 'LOW'
    reconstruction: str = ''
    report: str = ''
    cleaned_source: str = ''


# ==========================================================================
# Tokenizer: split Lua source into (kind, text) tokens
# ==========================================================================

@dataclass
class Tok:
    kind: str        # 'str' | 'num' | 'name' | 'op' | 'kw' | 'comment' | 'ws'
    text: str
    start: int
    end: int


DEO_KEYWORDS = {
    'and', 'break', 'do', 'else', 'elseif', 'end', 'false', 'for',
    'function', 'goto', 'if', 'in', 'local', 'nil', 'not', 'or',
    'repeat', 'return', 'then', 'true', 'until', 'while',
}


def tokenize(src: str):
    toks = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        # whitespace
        if c in ' \t\r\n':
            j = i
            while j < n and src[j] in ' \t\r\n':
                j += 1
            toks.append(Tok('ws', src[i:j], i, j))
            i = j
            continue
        # comments
        if c == '-' and src[i + 1:i + 2] == '-':
            if src[i + 2:i + 4] == '[[':
                close = src.find(']]', i + 2)
                j = (close + 2) if close != -1 else n
            else:
                nl = src.find('\n', i)
                j = (nl + 1) if nl != -1 else n
            toks.append(Tok('comment', src[i:j], i, j))
            i = j
            continue
        # long brackets
        if c == '[' and src[i + 1:i + 2] == '[':
            close = src.find(']]', i + 2)
            if close != -1:
                toks.append(Tok('str', src[i:close + 2], i, close + 2))
                i = close + 2
                continue
        # short strings
        if c in ('"', "'"):
            j = i + 1
            while j < n:
                if src[j] == '\\':
                    j += 2
                elif src[j] == c:
                    j += 1
                    break
                else:
                    j += 1
            toks.append(Tok('str', src[i:j], i, j))
            i = j
            continue
        # numbers
        if c.isdigit() or (c == '.' and src[i + 1:i + 2].isdigit()):
            j = i
            while j < n and (src[j].isalnum() or src[j] in '.'):
                j += 1
            toks.append(Tok('num', src[i:j], i, j))
            i = j
            continue
        # names
        if c.isalpha() or c == '_':
            j = i
            while j < n and (src[j].isalnum() or src[j] == '_'):
                j += 1
            w = src[i:j]
            toks.append(Tok('kw' if w in DEO_KEYWORDS else 'name', w, i, j))
            i = j
            continue
        # operators (longest match)
        for op in ('...', '..', '==', '~=', '<=', '>=', '::'):
            if src.startswith(op, i):
                toks.append(Tok('op', op, i, i + len(op)))
                i += len(op)
                break
        else:
            toks.append(Tok('op', c, i, i + 1))
            i += 1
    return toks


# ==========================================================================
# STAGE 0/1 helpers: banner, IIFE
# ==========================================================================

def strip_banner(source: str) -> str:
    s = source.strip()
    m = re.match(r'^--\[\[.*?\]\]', s, flags=re.S)
    return s[m.end():].strip() if m else s


def _match_balanced(src: str, open_pos: int):
    """Given '(' at open_pos, find matching ')' position (exclusive end)."""
    depth = 0
    i = open_pos
    n = len(src)
    in_str = None
    while i < n:
        c = src[i]
        if in_str:
            if c == '\\':
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c in ('"', "'"):
            in_str = c
        elif c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def _split_args(text: str) -> list:
    """Split top-level comma-separated expressions (string-aware)."""
    parts, cur, depth, in_str = [], [], 0, None
    i = 0
    while i < len(text):
        c = text[i]
        if in_str:
            if c == '\\':
                cur.append(text[i:i + 2])
                i += 2
                continue
            if c == in_str:
                in_str = None
            cur.append(c)
        elif c in ('"', "'"):
            in_str = c
            cur.append(c)
        elif c in '([{':
            depth += 1
            cur.append(c)
        elif c in ')]}':
            depth -= 1
            cur.append(c)
        elif c == ',' and depth == 0:
            parts.append(''.join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    if cur:
        parts.append(''.join(cur))
    return [p.strip() for p in parts]


def extract_iife(source: str):
    """
    Match   return(function(params, ...) ... end)(args)
    Returns (params, body, args) or None.

    All scanning is string/escape-aware because the alphabets and pool
    entries legitimately contain '(' ')' '{' '}' ',' ';' characters.
    """
    src = strip_banner(source)
    m = re.match(r'^return\s*\(\s*function\s*\(', src)
    if not m:
        return None
    fn_paren = m.end() - 1                     # '(' right after 'function'
    p_close = _match_balanced(src, fn_paren)   # index AFTER matching ')'
    if p_close == -1:
        return None
    params_src = src[fn_paren + 1:p_close - 1]
    params = [p.strip() for p in _split_args(params_src) if p.strip()]

    # body: from p_close to the matching 'end' of this function, then ')('
    # find the last 'end)(' at depth 0 outside strings
    idx = -1
    i, n, depth, in_str = p_close, len(src), 0, None
    while i < n:
        c = src[i]
        if in_str:
            if c == '\\':
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c in ('"', "'"):
            in_str = c
        elif c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
        elif src.startswith('end)(', i):
            idx = i
        i += 1
    if idx == -1:
        return None
    body = src[p_close:idx + 3]                # includes 'end)'
    invoc_open = idx + 4                       # position of '('
    invoc_close = _match_balanced(src, invoc_open)
    if invoc_close == -1:
        return None
    args_src = src[invoc_open + 1:invoc_close - 1]
    args = _split_args(args_src)
    return params, body, args


# ==========================================================================
# STAGE 2: constant folding
# ==========================================================================

def fold_constants(body: str):
    """Fold a+b / a-b / a%b arithmetic camouflage into literal ints.
    Returns (folded_body, [(expr, value)])."""
    found = []

    def repl(m):
        a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
        if op == '+':
            v = a + b
        elif op == '-':
            v = a - b
        else:
            v = a % b
        found.append((m.group(0), v))
        return str(v)

    pat = re.compile(r'(?<![\w.])(-?\d{5,})\s*([+\-%])\s*(-?\d{3,})(?![\w.])')
    folded = pat.sub(repl, body)
    # Collapse redundant parentheses around plain integers that remain after
    # folding, so downstream patterns see bare digits:
    #   L==(1165)  ->  L==1165 ;  K(S((-19737))) -> K(S(-19737))
    # Safety rules (semantic-preserving only):
    #   * never touch parens preceded by an identifier (f(123)), a '.' or a
    #     closing bracket/quote (real call/index/constructor syntax)
    #   * a NEGATIVE number keeps its parens unless the '(' is preceded by a
    #     character that cannot continue an arithmetic expression, because
    #     `x-(-1)` != `x--1` (and `--` even opens a comment in Lua)
    collapse = re.compile(r'(?<![\w.\)\]"\'])\((-?\d+)\)')

    def _drop(m):
        num = m.group(1)
        if num.startswith('-'):
            start = m.start()
            prev = folded[start - 1] if start else ''
            if prev and prev not in '(\[{,;=:':
                return m.group(0)          # keep parentheses
        return num

    for _ in range(4):
        nxt = collapse.sub(_drop, folded)
        if nxt == folded:
            break
        folded = nxt
    return folded, found


# ==========================================================================
# STAGE 3: string pool extraction
# ==========================================================================

def extract_pool(body: str, args: list = None):
    """
    Recover the string pool. Two supported shapes:

    Path A (varargs style, the canonical WeAreDevs layout):
        the pool is passed as trailing IIFE invocation arguments, captured
        by `local U={...}` inside the body. Every argument that is a quoted
        string literal is one pool entry (the runtime primitives before
        them are identifiers / parenthesised expressions, never literals).

    Path B (literal table style):
        `local U={"e1","e2",...}` directly in the body.

    Returns (pool_var_name, [entry_str]) or (None, []).
    """
    if args:
        entries, started = [], False
        for a in args:
            a = a.strip()
            if len(a) >= 2 and a[0] in ('"', "'") and a[-1] == a[0] \
                    and not _has_unescaped(a[1:-1], a[0]):
                try:
                    entries.append(_decode_lit(a))
                    started = True
                    continue
                except Exception:
                    pass
            if started:
                break                      # pool finished at first non-literal
        if entries:
            m = re.search(r'local\s+(\w+)\s*=\s*\{\s*\.\.\.\s*\}', body)
            return (m.group(1) if m else 'U(varargs)'), entries
    # Path B: local U = {...} literal table (string-aware scan)
    m = re.search(r'local\s+(\w+)\s*=\s*\{(?![^\n]*\.\.\.)', body)
    if m:
        var = m.group(1)
        open_pos = body.index('{', m.start() + len(m.group(0)) - 1)
        close = _match_table_close(body, open_pos)
        if close == -1:
            return None, []
        inner = body[open_pos + 1:close - 1]
        entries = parse_table_entries(inner)
        return var, entries
    return None, []


def _has_unescaped(s: str, q: str) -> bool:
    """True if the quote char q appears unescaped inside s."""
    i = 0
    while i < len(s):
        if s[i] == '\\':
            i += 2
            continue
        if s[i] == q:
            return True
        i += 1
    return False


def _match_table_close(src: str, open_pos: int):
    depth = 0
    i = open_pos
    n = len(src)
    in_str = None
    while i < n:
        c = src[i]
        if in_str:
            if c == '\\':
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c in ('"', "'"):
            in_str = c
        elif c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def parse_table_entries(inner: str) -> list:
    """Parse top-level comma-separated entries of a Lua table constructor."""
    if not inner.strip():
        return []
    entries = []
    for part in _split_args(inner):
        part = part.strip()
        # string literal?
        if part.startswith('"') and part.endswith('"'):
            try:
                entries.append(_decode_lit(part))
            except Exception:
                entries.append(part)
        elif part.startswith("'") and part.endswith("'"):
            try:
                entries.append(_decode_lit(part))
            except Exception:
                entries.append(part)
        else:
            entries.append(part)
    return entries


def _decode_lit(lit: str) -> str:
    """Decode a Lua string literal (without surrounding quotes) -> str."""
    return decode_lua_string(lit[1:-1]).decode('latin-1')


# ==========================================================================
# STAGE 4: permutation simulation
# ==========================================================================

_PERM_RE = re.compile(
    r'local\s+a,b\s*=\s*([\d,]+)\s*\n'
    r'for\s+i\s*=\s*([\d,]+)\s*,\s*([\d,]+)\s*do\s*\n'
    r'(?:.*?\n)?'
    r'U\[a\],U\[b\]\s*=\s*U\[b\],U\[a\]\s*\n'
    r'if\s+b\s*==\s*([\d,]+)\s*then\s+a,b\s*=\s*([\d,]+)\s*,\s*([\d,]+)\s*'
    r'else\s+a,b\s*=\s*a\s*\+\s*([\d,]+)\s*,\s*b\s*\+\s*([\d,]+)\s*end\s*\n'
    r'end',
    re.S,
)


def extract_permutation(body: str, n: int):
    """
    Detect the canonical swap loop and simulate it.
    Returns (iterations, description) or (0, '').
    """
    m = re.search(
        r'for\s+i\s*=\s*\(?\s*(-?\d+)\s*\)?\s*,\s*\(?\s*(-?\d+)\s*\)?\s*do\s*\n'
        r'\s*U\[a\],U\[b\]\s*=\s*U\[b\],U\[a\]\s*\n'
        r'\s*if\s+b\s*==\s*(\d+)\s*then\s+a,b\s*=\s*(\d+),(\d+)\s*'
        r'else\s+a,b\s*=\s*a\s*\+\s*(\d+),\s*b\s*\+\s*(\d+)\s*end\s*\n'
        r'\s*end',
        body,
    )
    if not m:
        return 0, ''
    lo, hi = int(m.group(1)), int(m.group(2))
    iterations = hi - lo + 1
    desc = (
        f"canonical adjacent-swap loop, {iterations} iterations "
        f"(= {iterations // (n - 1)} full passes, left-rotation) on n={n}"
    )
    return iterations, desc


def apply_permutation(entries: list, iterations: int):
    """Simulate the Lua swap loop exactly (returns final ordering).

    Mirrors obfuscator.engine.simulate_permutation:
        local a,b = 1,2
        for i = 0, T-1 do
          U[a],U[b] = U[b],U[a]
          if b == n then a,b = 1,2 else a,b = a+1,b+1 end
        end
    """
    n = len(entries)
    final = simulate_permutation(n, iterations)   # 1-based positions
    return [entries[p - 1] for p in final]


# ==========================================================================
# STAGE 5: dictionaries
# ==========================================================================

def extract_dictionaries(body: str):
    """
    Find `local o = { ... }` / `local w = { ... }` char tables.
    Returns dict name -> list of characters (in index order).
    """
    dicts = {}
    for m in re.finditer(r'local\s+(\w+)\s*=\s*\{', body):
        var = m.group(1)
        open_pos = body.index('{', m.start() + len(m.group(0)) - 1)
        close = _match_table_close(body, open_pos)
        if close == -1:
            continue
        inner = body[open_pos + 1:close - 1]
        # only single-char string entries
        chars = []
        ok = True
        for part in _split_args(inner):
            part = part.strip()
            if len(part) >= 3 and part[0] in '"\'' and part[-1] == part[0]:
                try:
                    ch = _decode_lit(part)
                    if len(ch) == 1:
                        chars.append(ch)
                        continue
                except Exception:
                    pass
            ok = False
            break
        if ok and len(chars) in (64, 85):
            dicts[var] = chars
    return dicts


# ==========================================================================
# STAGE 6/7: decode all pool entries
# ==========================================================================

def decode_pool_entries(entries: list, b85: bytes, b64: bytes):
    """
    Decode every entry using the recovered alphabets.
    Branch marker first char: 'l' base85 / 's' base64 / '?' plaintext.
    """
    out = []
    for i, ent in enumerate(entries, start=1):
        if not isinstance(ent, str) or not ent:
            out.append(DecodedString(i, str(ent), '?', str(ent).encode('latin-1')))
            continue
        mark = ent[0]
        rest = ent[1:]
        if mark == 'l':
            data = b85_decode(rest, b85)
            out.append(DecodedString(i, ent, 'l', data))
        elif mark == 's':
            data = (b64_decode(rest, b64) if rest else b'')
            out.append(DecodedString(i, ent, 's', data))
        else:
            out.append(DecodedString(i, ent, '?', rest.encode('latin-1')))
    return out


def verify_roundtrip(decoded: list, b85: bytes, b64: bytes) -> list:
    """RULE 49: re-encode each decoded string; must be byte-exact."""
    problems = []
    for d in decoded:
        if d.branch == 'l':
            re_enc = 'l' + b85_encode(d.decoded_bytes, b85)
        elif d.branch == 's':
            re_enc = 's' + (b64_encode(d.decoded_bytes, b64) if d.decoded_bytes else '')
        else:
            re_enc = d.encoded
        if re_enc != d.encoded:
            problems.append((d.index, d.encoded, re_enc))
    return problems


# ==========================================================================
# STAGE 8: VM analysis
# ==========================================================================

@dataclass
class VMState:
    id: int
    lines: list
    next: int | None      # None -> terminal


def extract_vm_states(dispatch_src: str):
    """
    Extract states from the flattened dispatcher:
        local Z,I,L={...}
        while L do
        if L==(ID) then
         ...
        L=(NEXT)
        elseif L==(ID) then ...
        end
        end
    """
    states = []
    # find `while L do ... end end`
    m = re.search(r'while\s+(\w+)\s+do', dispatch_src)
    if not m:
        return [], None
    L = m.group(1)
    # split into `if/elseif L==ID then` branches
    pat = re.compile(
        r'(?:if|elseif)\s+' + re.escape(L) + r'\s*==\s*(\d+)\s*then\s*\n'
        r'(.*?)\n?\s*L\s*=\s*(\w+|\d+|nil)',
        re.S,
    )
    for m2 in pat.finditer(dispatch_src):
        sid = int(m2.group(1))
        lines = [ln.strip() for ln in m2.group(2).strip().split('\n') if ln.strip()]
        nxt = m2.group(3)
        if nxt.isdigit():
            nxt = int(nxt)
        states.append(VMState(sid, lines, nxt))
    return states, L


def find_entry_state(dispatch_src: str):
    """Entry state = value of L at initialisation."""
    m = re.search(r'local\s+Z,I,L\s*=\s*\{\},nil,(\d+)', dispatch_src)
    return int(m.group(1)) if m else None


# ==========================================================================
# STAGE 9: critical path
# ==========================================================================

def critical_path(states: list, entry: int):
    """
    RULE 71/72: walk reachable states only, from entry to terminal.
    Returns (path_ids, ops) and detects unreachable states.
    """
    by_id = {s.id: s for s in states}
    path = []
    cur = entry
    seen = set()
    ops = []
    while cur is not None and cur in by_id and cur not in seen:
        seen.add(cur)
        s = by_id[cur]
        path.append(cur)
        ops.append((cur, '; '.join(s.lines)))
        cur = s.next
    return path, ops, seen


# ==========================================================================
# STAGE 10: CALL recovery + payload
# ==========================================================================

_CALL_LINE_RE = re.compile(
    r'Z\[(\d+)\]\s*=\s*Z\[(\d+)\]\s*\(\s*un\s*\(\s*Z\[(\d+)\]\s*\)\s*\)'
)


def recover_calls(critical: list, states_by_id: dict):
    """
    Walk the critical path; reconstruct each CALL:
      Z[r] = Z[g](un(Z[a]))     -> funcname(arg1, arg2, ...)
    """
    calls = []
    for sid in critical:
        s = states_by_id[sid]
        for ln in s.lines:
            m = _CALL_LINE_RE.search(ln)
            if m:
                calls.append((sid, int(m.group(2)), int(m.group(3))))
    return calls


def build_payload(calls, states_by_id, consts, globals_, argpacks):
    """Reconstruct the payload source line by line."""
    lines = []
    for (sid, gz, az) in calls:
        fn = globals_.get(gz, '[UNKNOWN]')
        arg_exprs = []
        for z in argpacks.get(az, []):
            if z in consts:
                kind, val = consts[z]
                if kind == 'str':
                    arg_exprs.append(encode_lua_string(val))
                else:
                    arg_exprs.append(str(val))
            else:
                arg_exprs.append('[UNKNOWN]')
        lines.append(f"{fn}({', '.join(arg_exprs)})")
    return '\n'.join(lines) + '\n' if lines else ''


# ==========================================================================
# Generic pass: decode-only deobfuscation (any Lua source)
# ==========================================================================

_SIMPLE_DECODERS = [
    # \ddd escapes
    ('decimal-escapes',
     re.compile(r'(?:\\\d{1,3}){2,}'),
     lambda m: bytes(int(x) for x in re.findall(r'\\(\d{1,3})', m.group(0))).decode('latin-1', 'replace')),
    # \xHH escapes
    ('hex-escapes',
     re.compile(r'(?:\\x[0-9a-fA-F]{2}){2,}'),
     lambda m: bytes(int(x, 32 // 2) for x in re.findall(r'\\x([0-9a-fA-F]{2})', m.group(0))).decode('latin-1', 'replace')),
    # string.char chains
    ('string.char-chain',
     re.compile(r'string\.char\s*\(\s*([-\d\s,]+)\s*\)', ),
     lambda m: ''.join(chr(int(x) % 256) for x in m.group(1).split(','))),
    # string.char chains with math.floor camouflage
    ('string.char-chain-camo',
     re.compile(
         r'string\.char\s*\(\s*([^)]*)\)',
         re.S),
     lambda m: None),    # handled specially below
    ('base64-std',
     re.compile(r'"([A-Za-z0-9+/=]{8,})"'),
     lambda m: None),    # heuristic, handled specially
]


def generic_decode_pass(source: str):
    """
    Generic single-layer decoders for non-WeAreDevs scripts:
      - \\ddd / \\xHH escape sequences
      - string.char chains (incl. folded math camouflage)
      - string.reverse + escapes
      - single-byte XOR with brute-forced key 1..255
      - standard Base64 blobs (heuristic)
    Returns list of (method, decoded_string) findings.
    """
    findings = []
    # decimal escapes
    for m in re.finditer(r'(?:\\\d{1,3}){2,}', source):
        try:
            data = bytes(int(x) & 0xFF for x in re.findall(r'\\(\d{1,3})', m.group(0)))
            text = data.decode('latin-1')
            if _looks_texty(text):
                findings.append(('decimal-escape', text))
        except Exception:
            pass
    # hex escapes
    for m in re.finditer(r'(?:\\x[0-9a-fA-F]{2}){2,}', source):
        try:
            data = bytes(int(x, 16) for x in re.findall(r'\\x([0-9a-fA-F]{2})', m.group(0)))
            text = data.decode('latin-1')
            if _looks_texty(text):
                findings.append(('hex-escape', text))
        except Exception:
            pass
    # string.char chains
    for m in re.finditer(r'string\.char\s*\(\s*([-\d\s,]+?)\s*\)', source):
        try:
            text = ''.join(chr(int(x) % 256) for x in m.group(1).split(','))
            if _looks_texty(text):
                findings.append(('string.char-chain', text))
        except Exception:
            pass
    # string.char with arithmetic camouflage inside
    folded, _ = fold_constants(source)
    for m in re.finditer(r'string\.char\s*\(\s*([-\d\s,]+?)\s*\)', folded):
        try:
            text = ''.join(chr(int(x) % 256) for x in m.group(1).split(','))
            if _looks_texty(text):
                findings.append(('string.char-chain-camo', text))
        except Exception:
            pass
    # single-byte XOR brute force on printable runs.
    # Plaintext is usually *word-like*: mostly letters/spaces, not the
    # random symbol soup that a wrong key produces.
    for m in re.finditer(r'"([A-Za-z0-9+/=]{12,})"', source):
        blob = m.group(1)
        for key in range(1, 256):
            data = bytes((ord(c) ^ key) for c in blob)
            try:
                text = data.decode('latin-1')
            except Exception:
                continue
            if _looks_wordy(text):
                findings.append(('xor-bruteforce', text))
                break
    # standard base64 (heuristic, only if it fully decodes to texty data)
    import base64 as _b64
    for m in re.finditer(r'"([A-Za-z0-9+/]{16,}={0,2})"', source):
        blob = m.group(1)
        try:
            data = _b64.b64decode(blob, validate=True)
            text = data.decode('latin-1')
            if _looks_texty(text, strict=True):
                findings.append(('base64-std', text))
        except Exception:
            pass
    return findings


def _looks_texty(text: str, strict: bool = False) -> bool:
    if not text:
        return False
    printable = sum(1 for c in text if 32 <= ord(c) < 127 or c in '\n\r\t')
    ratio = printable / len(text)
    if strict:
        return ratio > 0.95 and len(text) >= 4
    return ratio > 0.85 and len(text) >= 3


def _looks_wordy(text: str) -> bool:
    """Stricter heuristic for XOR/encoded candidates: the result should
    look like human text (letters and spaces dominate, no symbol soup)."""
    if len(text) < 8:
        return False
    if not all(32 <= ord(c) < 127 for c in text):
        return False
    letters = sum(1 for c in text if c.isalpha())
    spaces = sum(1 for c in text if c == ' ')
    ratio = (letters + spaces) / len(text)
    if ratio < 0.85:
        return False
    if spaces == 0:
        # a single long word is fine, but require a vowel somewhere
        if not any(c in 'aeiouAEIOU' for c in text):
            return False
    return True


# ==========================================================================
# Main entry point
# ==========================================================================

def deobfuscate(source: str) -> DeobfuscationResult:
    res = DeobfuscationResult()
    res.source_length = len(source)
    res.ok = True

    # ---------- STAGE 0: preflight ----------
    banner_m = re.match(r'^--\[\[\s*(.*?)\s*\]\]', source.strip(), re.S)
    res.banner = banner_m.group(1) if banner_m else None

    iife = extract_iife(source)
    if iife is None:
        # ---------- generic path ----------
        findings = generic_decode_pass(source)
        res.method = 'generic'
        res.payload = '\n'.join(f"-- [{m}] {t}" for m, t in findings)
        res.cleaned_source = source
        res.payload_status = ('PARTIALLY RECOVERED' if findings
                              else 'NOT RECOVERED')
        res.report = _report_generic(res, findings)
        return res

    params, body, args = iife
    res.method = 'layered'
    res.iife_params = params
    res.primitives = {p: a for p, a in zip(params, args)}

    # ---------- STAGE 2: constant folding ----------
    folded, found = fold_constants(body)
    res.constants = found[:60]

    # ---------- STAGE 3: pool ----------
    var, entries = extract_pool(folded, args)
    if var is None:
        findings = generic_decode_pass(source)
        res.method = 'layered-partial (no pool)'
        res.payload = '\n'.join(f"-- [{m}] {t}" for m, t in findings)
        res.payload_status = 'PARTIALLY RECOVERED' if findings else 'NOT RECOVERED'
        res.report = _report_generic(res, findings)
        return res
    n = len(entries)

    # ---------- STAGE 4: permutation ----------
    iterations, perm_desc = extract_permutation(folded, n)
    if iterations:
        entries = apply_permutation(entries, iterations)
        res.permutation = perm_desc
    else:
        res.permutation = 'none detected'

    # ---------- STAGE 5: dictionaries ----------
    dicts = extract_dictionaries(folded)
    b85 = b64 = None
    for name, chars in dicts.items():
        alpha = ''.join(chars).encode('latin-1')
        if len(alpha) == 85:
            b85 = alpha
        elif len(alpha) == 64:
            b64 = alpha
    if b85 is None or b64 is None:
        # try standard alphabets (fallback)
        if b85 is None:
            b85 = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"
        if b64 is None:
            b64 = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/"

    # ---------- STAGE 6/7: decode + verify ----------
    decoded = decode_pool_entries(entries, b85, b64)
    problems = verify_roundtrip(decoded, b85, b64)
    res.pool = decoded

    # ---------- STAGE 8: VM states ----------
    states, L = extract_vm_states(folded)
    entry = find_entry_state(folded) if states else None
    res.vm_states = [(s.id, s.lines, s.next) for s in states]

    # ---------- STAGE 9: critical path ----------
    if states and entry is not None:
        path, ops, seen = critical_path(states, entry)
        res.critical_path = ops
        states_by_id = {s.id: s for s in states}
        unreachable = [s.id for s in states if s.id not in seen]

        # ---------- STAGE 10: registers ----------
        consts, globals_, argpacks = extract_registers(states, path, decoded, folded)
        calls = recover_calls(path, states_by_id)
        payload = build_payload(calls, states_by_id, consts, globals_, argpacks)
        res.payload = payload
        res.cleaned_source = payload

        # trace
        for step, (sid, op) in enumerate(ops, 1):
            res.trace.append((step, f"STATE {sid}: {op}"))
        if calls:
            res.payload_status = 'FULLY RECOVERED' if not problems else 'PARTIALLY RECOVERED'
            res.confidence = 'HIGH' if not problems else 'MEDIUM'
            res.reconstruction = payload
        else:
            res.payload_status = 'PARTIALLY RECOVERED'
            res.confidence = 'MEDIUM'
            res.reconstruction = payload
        if unreachable:
            res.trace.append((len(res.trace) + 1,
                              f"[INFO] {len(unreachable)} unreachable decoy states ignored"))
        if problems:
            res.trace.append((len(res.trace) + 1,
                              f"[WARN] {len(problems)} round-trip mismatches"))
    else:
        # no VM: strings-only recovery
        executed = [d for d in decoded if d.classification != 'DECOY']
        res.payload = '\n'.join(
            f'-- decoded pool entry {d.index}: {d.decoded_bytes.decode("latin-1")!r}'
            for d in decoded)
        res.cleaned_source = _general_reconstruct(source, folded, decoded, b85, b64)
        res.payload_status = 'PARTIALLY RECOVERED'
        res.confidence = 'MEDIUM'
        res.reconstruction = res.cleaned_source

    # ---------- STAGE 12: report ----------
    res.report = build_report(res)
    return res


# ==========================================================================
# Register extraction from critical path
# ==========================================================================

def extract_registers(states, path, decoded, folded):
    """
    Walk the critical path; map virtual registers:
      Z[k]=K(S(idx))  -> consts[k] = ('str', decoded_bytes)
      Z[k]=E["name"]  -> globals_[k] = name
      Z[k]={...}      -> argpacks[k] = [register ids]
      Z[k]=<number>   -> consts[k] = ('num', value)
    """
    consts, globals_, argpacks = {}, {}, {}
    by_id = {s.id: s for s in states}
    # find S offset from `local function S(x) return U[x+(BIG)] end`
    m = re.search(
        r'function\s+S\s*\(\s*\w+\s*\)\s*return\s+U\s*\[\s*\w+\s*\+\s*'
        r'\(?\s*([-\d]+)\s*\)?\s*\]', folded)
    offset = int(m.group(1)) if m else 0
    for sid in path:
        s = by_id[sid]
        for ln in s.lines:
            m2 = re.match(r'Z\[(\d+)\]\s*=\s*K\s*\(\s*S\s*\(\s*([-\d]+)\s*\)\s*\)', ln)
            if m2:
                z, idx = int(m2.group(1)), int(m2.group(2))
                real = idx + offset
                if 1 <= real <= len(decoded):
                    consts[z] = ('str', decoded[real - 1].decoded_bytes)
                continue
            m3 = re.match(r'Z\[(\d+)\]\s*=\s*E\s*\[\s*"([^"]+)"\s*\]', ln)
            if m3:
                globals_[int(m3.group(1))] = m3.group(2)
                continue
            m4 = re.match(r'Z\[(\d+)\]\s*=\s*\{\s*([^}]*)\s*\}', ln)
            if m4 and 'Z[' in m4.group(2):
                z = int(m4.group(1))
                argpacks[z] = [int(x) for x in re.findall(r'Z\[(\d+)\]', m4.group(2))]
                continue
            m5 = re.match(r'Z\[(\d+)\]\s*=\s*(-?\d+)$', ln)
            if m5:
                consts[int(m5.group(1))] = ('num', m5.group(2))
    return consts, globals_, argpacks


# ==========================================================================
# Reconstruction for general (non-VM) layered scripts
# ==========================================================================

def _general_reconstruct(source, folded, decoded, b85, b64):
    """
    Replace K(S(idx)) / S(idx) calls with their decoded literal values.
    """
    m = re.search(
        r'function\s+S\s*\(\s*\w+\s*\)\s*return\s+U\s*\[\s*\w+\s*\+\s*'
        r'\(?\s*([-\d]+)\s*\)?\s*\]', folded)
    offset = int(m.group(1)) if m else 0

    def repl(m2):
        idx = int(m2.group(1)) + offset
        if 1 <= idx <= len(decoded):
            data = decoded[idx - 1].decoded_bytes
            return encode_lua_string(data)
        return m2.group(0)

    out = re.sub(r'K\s*\(\s*S\s*\(\s*([-\d]+)\s*\)\s*\)', repl, folded)
    out = re.sub(r'S\s*\(\s*([-\d]+)\s*\)', repl, out)
    # Strip the runtime scaffold: everything after the DECODER's own block.
    # The K function contains nested if/for blocks, so a lazy regex would
    # stop at the first inner `end` - use a block-depth scanner instead.
    k_start = re.search(r'local\s+function\s+K\s*\(', out)
    if k_start:
        k_end = _lua_block_end(out, k_start.start())
        if k_end != -1:
            tail = out[k_end:]
            tail = re.sub(r'^\s*local function _w2\(\)\n', '', tail)
            tail = re.sub(r'\n?\s*local I=_w1\(\)\nreturn un\(I\)\n?$', '', tail)
            tail = tail.replace('local Z,I,L={},nil,', '-- [VM init] ')
            tail = tail.replace('while L do', '-- [VM dispatcher] ')
            # drop the IIFE wrapper's own closing `end` (last line)
            tail = re.sub(r'\nend\s*\n?$', '\n', tail)
            return tail.strip() + '\n'
    return out


def _lua_block_end(src: str, fn_start: int) -> int:
    """
    Given the position of `local function K(` (or any `function` header),
    return the offset just past the matching `end` of that block.
    Depth rules: function/if/for/while open (+1), `end` closes (-1);
    `do` is ignored because every for/while header carries its own `do`.
    String/comment aware.
    """
    i, n = fn_start, len(src)
    depth = 0
    started = False
    in_str = None
    while i < n:
        c = src[i]
        if in_str:
            if c == '\\':
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c in ('"', "'"):
            in_str = c
            i += 1
            continue
        if src.startswith('--', i):
            if src.startswith('[[', i + 2):
                close = src.find(']]', i + 2)
                i = (close + 2) if close != -1 else n
            else:
                nl = src.find('\n', i)
                i = (nl + 1) if nl != -1 else n
            continue
        if c.isalpha() or c == '_':
            j = i
            while j < n and (src[j].isalnum() or src[j] == '_'):
                j += 1
            word = src[i:j]
            if word in ('function', 'if', 'for', 'while'):
                depth += 1
                started = True
            elif word == 'end' and started:
                depth -= 1
                if depth == 0:
                    # skip trailing whitespace/newline after `end`
                    k = j
                    while k < n and src[k] in ' \t\r\n':
                        k += 1
                    return k
            i = j
            continue
        i += 1
    return -1


# ==========================================================================
# Reports
# ==========================================================================

def build_report(res: DeobfuscationResult) -> str:
    lines = []
    A = lines.append
    A("=== 1. OBFUSCATION ARCHITECTURE ===")
    if res.method.startswith('layered'):
        A(f"Banner: {res.banner or '(none)'}")
        A(f"Outer IIFE: PRESENT ({len(res.iife_params)} named params)")
        # the `...` rest-parameter is not a primitive; drop it from the listing
        prims = {k: v for k, v in res.primitives.items() if k != '...'}
        prim_list = ', '.join(f"{k}={v}" for k, v in prims.items())
        n_pool = len(res.pool)
        prim_list += (f", ...({n_pool} varargs = string pool)"
                      if n_pool else ", ...")
        A(f"Runtime primitives passed as arguments: {prim_list}")
        A(f"Layers: IIFE -> string pool -> permutation -> dictionaries -> "
          f"custom decoder -> VM dispatcher -> payload")
    else:
        A("Generic/simple obfuscation (no WeAreDevs-style IIFE found).")
    A("")
    A("=== 2. SIMPLIFIED CONSTANTS ===")
    if res.constants:
        A("Expression | Value | Note")
        for (expr, val) in res.constants[:30]:
            A(f"{expr} | {val} | arithmetic camouflage")
        if len(res.constants) > 30:
            A(f"... {len(res.constants) - 30} more")
    else:
        A("None found.")
    A("")
    A("=== 3. STRING POOL ===")
    if res.pool:
        A(f"{len(res.pool)} entries (post-permutation ordering):")
        for d in res.pool:
            preview = d.decoded_bytes[:48]
            try:
                text = preview.decode('latin-1')
                shown = repr(text)
            except Exception:
                shown = preview.hex()
            A(f"  U[{d.index}] ({d.branch} branch) = {shown}")
    else:
        A("No pool found.")
    A("")
    A("=== 4. CHARACTER DICTIONARIES ===")
    if res.b85_alphabet:
        A(f"base-85 alphabet (custom, shuffled): {res.b85_alphabet.decode('latin-1')}")
    if res.b64_alphabet:
        A(f"base-64 alphabet (custom, shuffled): {res.b64_alphabet.decode('latin-1')}")
    A("")
    A("=== 5. STRING DECODER ===")
    A("Custom base-85 ('l' branch, 5 digits -> 4 bytes) + custom base-64 "
      "('s' branch, 4 digits -> 3 bytes) + '?' decoy passthrough.")
    A("")
    A("=== 6. DECODED STRINGS ===")
    A("(see STRING POOL above - every entry decoded and round-trip verified)")
    A("")
    A("=== 7. VM / CONTROL FLOW ===")
    if res.vm_states:
        A(f"Flattened state-machine dispatcher: {len(res.vm_states)} states "
          f"detected (incl. decoys); critical path = {len(res.critical_path)} states.")
    else:
        A("No VM dispatcher detected (payload embedded directly).")
    A("")
    A("=== 8. REGISTER / STATE MAP ===")
    if res.critical_path:
        for (sid, op) in res.critical_path:
            A(f"  STATE {sid}: {op}")
    A("")
    A("=== 9. RECOVERED API CALLS ===")
    apis = sorted({g for g in _globals_used(res)})
    A(', '.join(apis) if apis else 'none proven')
    A("")
    A("=== 10. RECOVERED PAYLOAD ===")
    A(res.payload or '[UNKNOWN]')
    A("")
    A("=== 11. FINAL EXECUTION TRACE ===")
    for (step, text) in res.trace:
        A(f"  Step {step}: {text}")
    if not res.trace:
        A("  [UNKNOWN: no VM execution trace - payload embedded directly]")
    A("")
    A("=== 12. UNKNOWN / UNRESOLVED ===")
    unresolved = [t for (_s, t) in res.trace if '[UNKNOWN' in t or '[WARN' in t]
    if unresolved:
        for u in unresolved:
            A(f"  {u}")
    else:
        A("  None - every recovered value was round-trip verified.")
    A("")
    A("=== 13. FINAL PAYLOAD STATUS ===")
    A(res.payload_status)
    A("")
    A(f"=== 14. FINAL SUMMARY ===")
    if res.method.startswith('layered'):
        A(f"The script is a WeAreDevs-style layered obfuscation of a "
          f"{'virtualized pure-call payload' if res.vm_states else 'direct payload'}. "
          f"Decoded pool: {len(res.pool)} entries. "
          f"Critical path: {len(res.critical_path)} states. "
          f"Payload status: {res.payload_status} (confidence {res.confidence}).")
    else:
        A(f"Generic obfuscation decoded via simple-layer pass; "
          f"{len(res.pool)} findings.")
    return '\n'.join(lines) + '\n'


def _globals_used(res):
    out = []
    for (sid, op) in res.critical_path:
        for m in re.finditer(r'Z\[\d+\]\s*=\s*E\s*\[\s*"([^"]+)"\s*\]', op):
            out.append(m.group(1))
    return out


def _report_generic(res, findings):
    lines = []
    lines.append("=== GENERIC DEOBFUSCATION REPORT ===")
    lines.append(f"Source length: {res.source_length} chars")
    lines.append(f"No WeAreDevs-style IIFE layer detected.")
    lines.append("")
    lines.append("=== FINDINGS ===")
    if findings:
        for method, text in findings[:50]:
            lines.append(f"[{method}] {text!r}")
        if len(findings) > 50:
            lines.append(f"... {len(findings) - 50} more")
    else:
        lines.append("No decodable strings found - source may be "
                     "plaintext or use an unsupported scheme.")
    lines.append("")
    lines.append(f"PAYLOAD STATUS: {res.payload_status}")
    return '\n'.join(lines) + '\n'

# ==========================================================================
# DISCORD BOT
# ==========================================================================

# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------
load_dotenv()

TOKEN = os.getenv('DISCORD_TOKEN')
if not TOKEN:
    print('ERROR: DISCORD_TOKEN is not set. Copy .env.example to .env '
          'and paste your bot token (see README.md, step 3).',
          file=sys.stderr)
    sys.exit(1)

MAX_FILE_KB = int(os.getenv('MAX_FILE_KB', '200'))          # upload cap
MAX_FILE_BYTES = MAX_FILE_KB * 1024
PROCESS_TIMEOUT = float(os.getenv('PROCESS_TIMEOUT', '25'))  # engine seconds
MAX_SOURCE_BYTES = 512 * 1024                                # engine hard cap
BANNER = os.getenv('BANNER', 'v1.0.1')

ALLOWED_EXTENSIONS = {'.lua', '.txt'}

# --------------------------------------------------------------------------
# Render free-tier keep-alive (optional)
#
# Render web services must bind an HTTP port to be considered "live", and
# free-tier web services sleep after ~15 minutes without inbound traffic.
# The bot is a long-lived process (Discord gateway), so:
#
#   * PORT  - when set (Render injects this automatically), a tiny HTTP
#             health server binds it and answers GET/HEAD /health.
#   * KEEP_ALIVE_URL - when set, a daemon thread pings that URL every
#             SELF_PING_INTERVAL seconds (default 600s) so the free web
#             service never idles long enough to sleep. Point it at your
#             service's own /health URL (or use an external pinger such as
#             UptimeRobot / cron-job.org and leave this unset).
#
# When PORT is not set (local runs, VPS, Docker, paid Render Worker), the
# whole block is a no-op.
# --------------------------------------------------------------------------
PORT = int(os.getenv('PORT', '0') or 0)            # 0 = disabled
SELF_PING_INTERVAL = float(os.getenv('SELF_PING_INTERVAL', '600'))
KEEP_ALIVE_URL = (os.getenv('KEEP_ALIVE_URL') or '').strip()

_health_server = None
_self_ping_stop = threading.Event()

bot = commands.Bot(
    # '.' is the primary prefix; '!' kept as a courtesy fallback
    command_prefix=commands.when_mentioned_or('.', '!'),
    intents=discord.Intents.default(),
    help_command=None,
    activity=discord.Activity(type=discord.ActivityType.watching,
                              name='for .obfuscate | .deobfuscate'),
)

# --------------------------------------------------------------------------
# stats
# --------------------------------------------------------------------------
_stats = {
    'start': time.time(),
    'obfuscated': 0,
    'deobfuscated': 0,
    'bytes_obfuscated': 0,
    'bytes_deobfuscated': 0,
    'errors': 0,
}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _get_attachment(ctx_or_message) -> discord.Attachment | None:
    """Return the first .lua/.txt attachment, or None (with reason)."""
    msg = ctx_or_message.message if hasattr(ctx_or_message, 'message') \
        else ctx_or_message
    for att in msg.attachments:
        _, ext = os.path.splitext(att.filename.lower())
        if ext in ALLOWED_EXTENSIONS:
            return att
    return None


async def _read_attachment(att: discord.Attachment) -> str:
    """Download an attachment as text (latin-1: Lua bytes are 0-255)."""
    data = await att.read()
    if len(data) > MAX_FILE_BYTES:
        raise ValueError(
            f'File too large ({len(data) // 1024} KB > {MAX_FILE_KB} KB cap).')
    return data.decode('latin-1')


def _make_file(content: str, filename: str) -> discord.File:
    """Wrap text into a discord.File with an explicit filename."""
    buf = io.BytesIO(content.encode('latin-1', errors='replace'))
    buf.seek(0)
    return discord.File(buf, filename=filename)


def _base_name(att: discord.Attachment, new_ext: str) -> str:
    """sample.txt -> sample.obf.lua / sample.decoded.lua"""
    stem = os.path.splitext(os.path.basename(att.filename))[0]
    stem = stem.replace('.obf', '').replace('.decoded', '')
    return f'{stem}{new_ext}'


async def _run_engine(func, *args, **kwargs):
    """Run CPU-bound engine work in a worker thread with a timeout."""
    loop = asyncio.get_running_loop()
    return await asyncio.wait_for(
        loop.run_in_executor(None, func, *args, **kwargs),
        timeout=PROCESS_TIMEOUT,
    )


EMBED_COLOR_OK = 0x2ECC71
EMBED_COLOR_WARN = 0xE67E22
EMBED_COLOR_ERR = 0xE74C3C


def _embed(color, title, description=None):
    e = discord.Embed(title=title, colour=color)
    if description:
        e.description = description
    return e


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------
@bot.event
async def on_ready():
    print(f'Logged in as {bot.user} (id {bot.user.id})')
    print('Commands: .obfuscate (.obf) | .deobfuscate (.deobf) '
          '| .help | .ping | .stats')


@bot.command(name='obfuscate', aliases=['obf', 'protect'])
async def obfuscate_cmd(ctx, *, note: str = ''):
    """Obfuscate an attached .lua/.txt file (layered engine)."""
    att = _get_attachment(ctx)
    if att is None:
        _stats['errors'] += 1
        await ctx.reply(
            embed=_embed(
                EMBED_COLOR_ERR, 'No script attached',
                'Upload a **.lua** or **.txt** file together with the '
                '`.obfuscate` command.\n'
                'Example: attach `myscript.lua`, type `.obfuscate`, send.'),
            mention_author=False)
        return
    try:
        src = await _read_attachment(att)
        if len(src) > MAX_SOURCE_BYTES:
            raise ValueError('Script too large for the engine (512 KB cap).')
        obf = await _run_engine(
            ObfuscationEngine().obfuscate, src, BANNER)
        _stats['obfuscated'] += 1
        _stats['bytes_obfuscated'] += len(obf)
        file = _make_file(obf, _base_name(att, '.obf.lua'))
        e = _embed(
            EMBED_COLOR_OK, 'Obfuscated',
            f'`{att.filename}` ({len(src):,} B) → layered obfuscation '
            f'({len(obf):,} B, {len(obf) / max(len(src), 1):.1f}x).')
        e.add_field(name='Layers',
                    value='IIFE · pool · permutation · base-85/64 · '
                          'camouflage · VM', inline=False)
        e.add_field(name='Next step',
                    value='Send it back with `.deobfuscate` to get the '
                          'decoded payload + full report.', inline=False)
        await ctx.reply(embed=e, file=file, mention_author=False)
    except asyncio.TimeoutError:
        _stats['errors'] += 1
        await ctx.reply(embed=_embed(
            EMBED_COLOR_ERR, 'Timeout',
            f'Obfuscation exceeded {PROCESS_TIMEOUT:.0f}s — the script may '
            'be too large/complex.'), mention_author=False)
    except Exception as exc:
        _stats['errors'] += 1
        await ctx.reply(embed=_embed(
            EMBED_COLOR_ERR, 'Obfuscation failed', f'`{type(exc).__name__}: '
            f'{exc}`'), mention_author=False)


@bot.command(name='deobfuscate',
             aliases=['deobf', 'decode', 'unobfuscate', 'unobf'])
async def deobfuscate_cmd(ctx, *, note: str = ''):
    """Deobfuscate an attached obfuscated .lua/.txt file.

    Returns BOTH the decoded payload file and the full report file."""
    att = _get_attachment(ctx)
    if att is None:
        _stats['errors'] += 1
        await ctx.reply(
            embed=_embed(
                EMBED_COLOR_ERR, 'No script attached',
                'Upload a **.lua** or **.txt** file together with the '
                '`.deobfuscate` command.'),
            mention_author=False)
        return
    try:
        src = await _read_attachment(att)
        if len(src) > MAX_SOURCE_BYTES:
            raise ValueError('Script too large for the engine (512 KB cap).')
        res = await _run_engine(deobfuscate, src)

        decoded = (res.cleaned_source or res.payload or
                   '-- [nothing recovered] --\n')
        _stats['deobfuscated'] += 1
        _stats['bytes_deobfuscated'] += len(decoded)

        files = [
            _make_file(decoded, _base_name(att, '.decoded.lua')),
            _make_file(res.report or '', _base_name(att, '.report.txt')),
        ]

        color = (EMBED_COLOR_OK if res.confidence == 'HIGH'
                 else EMBED_COLOR_WARN if res.confidence == 'MEDIUM'
                 else EMBED_COLOR_ERR)
        e = _embed(color, f'Deobfuscation — {res.payload_status}',
                   f'`{att.filename}` → method: **{res.method}**')
        e.add_field(name='Confidence', value=res.confidence, inline=True)
        e.add_field(name='Pool entries', value=str(len(res.pool)), inline=True)
        if res.vm_states:
            e.add_field(name='VM states',
                        value=f"{len(res.vm_states)} "
                              f"({len(res.critical_path)} on critical path)",
                        inline=True)
        preview = (res.payload or '').strip()
        if preview:
            shown = preview[:300] + ('…' if len(preview) > 300 else '')
            e.add_field(name='Recovered payload', value=f'```\n{shown}\n```',
                        inline=False)
        await ctx.reply(embed=e, files=files, mention_author=False)
    except asyncio.TimeoutError:
        _stats['errors'] += 1
        await ctx.reply(embed=_embed(
            EMBED_COLOR_ERR, 'Timeout',
            f'Deobfuscation exceeded {PROCESS_TIMEOUT:.0f}s.'), mention_author=False)
    except Exception as exc:
        _stats['errors'] += 1
        await ctx.reply(embed=_embed(
            EMBED_COLOR_ERR, 'Deobfuscation failed',
            f'`{type(exc).__name__}: {exc}`'), mention_author=False)


@bot.command(name='help')
async def help_cmd(ctx):
    e = _embed(0x3498DB, 'Lua Obfuscator / Deobfuscator',
               'WeAreDevs-style layered obfuscation + full '
               'reverse-engineering pipeline.')
    e.add_field(
        name='.obfuscate  (.obf, .protect)',
        value='Attach a `.lua`/`.txt` file → get the obfuscated script back.',
        inline=False)
    e.add_field(
        name='.deobfuscate  (.deobf, .decode, .unobfuscate)',
        value='Attach an obfuscated file → get **both** the decoded payload '
              '`.lua` **and** the full 14-section report `.txt`.',
        inline=False)
    e.add_field(name='.ping', value='Bot latency.', inline=False)
    e.add_field(name='.stats', value='Session statistics.', inline=False)
    e.set_footer(text=f'Max {MAX_FILE_KB} KB per file · '
                      f'{PROCESS_TIMEOUT:.0f}s engine timeout')
    await ctx.reply(embed=e, mention_author=False)


@bot.command(name='ping')
async def ping_cmd(ctx):
    await ctx.reply(embed=_embed(
        EMBED_COLOR_OK, 'Pong',
        f'Gateway latency: **{bot.latency * 1000:.0f} ms**'),
        mention_author=False)


@bot.command(name='stats')
async def stats_cmd(ctx):
    up = time.time() - _stats['start']
    h, rem = divmod(int(up), 3600)
    m, s = divmod(rem, 60)
    e = _embed(0x9B59B6, 'Session statistics')
    e.add_field(name='Uptime', value=f'{h}h {m}m {s}s', inline=True)
    e.add_field(name='Scripts obfuscated',
                value=str(_stats['obfuscated']), inline=True)
    e.add_field(name='Scripts deobfuscated',
                value=str(_stats['deobfuscated']), inline=True)
    e.add_field(name='Bytes obfuscated',
                value=f"{_stats['bytes_obfuscated']:,}", inline=True)
    e.add_field(name='Bytes deobfuscated',
                value=f"{_stats['bytes_deobfuscated']:,}", inline=True)
    e.add_field(name='Errors', value=str(_stats['errors']), inline=True)
    await ctx.reply(embed=e, mention_author=False)


# --------------------------------------------------------------------------
# keep-alive health server (Render free web services)
# --------------------------------------------------------------------------
class _HealthHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler answering /health with a JSON status blob."""

    def _respond(self, send_body: bool):
        if self.path.split('?')[0].rstrip('/') in ('', '/health', '/healthz'):
            payload = {
                'status': 'ok',
                'bot': BANNER,
                'uptime_seconds': int(time.time() - _stats['start']),
                'obfuscated': _stats['obfuscated'],
                'deobfuscated': _stats['deobfuscated'],
                'errors': _stats['errors'],
            }
            body = json.dumps(payload).encode('ascii')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            if send_body:
                self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header('Content-Length', '0')
            self.end_headers()

    def do_GET(self):
        self._respond(send_body=True)

    def do_HEAD(self):
        self._respond(send_body=False)

    def log_message(self, fmt, *args):   # keep Render logs quiet
        pass


def _start_health_server():
    """Bind the health server on PORT if configured (Render web service)."""
    global _health_server
    if not PORT:
        return
    try:
        _health_server = ThreadingHTTPServer(('0.0.0.0', PORT), _HealthHandler)
        _health_server.daemon_threads = True
        threading.Thread(target=_health_server.serve_forever,
                         name='health-server', daemon=True).start()
        print(f'[keep-alive] health server listening on 0.0.0.0:{PORT}/health')
    except OSError as exc:
        # never let a port problem take the Discord bot down
        print(f'[keep-alive] WARNING: could not bind port {PORT}: {exc}')


def _self_ping_loop():
    """Ping KEEP_ALIVE_URL every SELF_PING_INTERVAL seconds (free tier)."""
    url = KEEP_ALIVE_URL
    while not _self_ping_stop.wait(SELF_PING_INTERVAL):
        try:
            req = urllib.request.Request(url, method='GET',
                                         headers={'User-Agent': 'lua-bot-keepalive'})
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read(64)
            print(f'[keep-alive] pinged {url} -> {resp.status}')
        except Exception as exc:  # noqa: BLE001 - best-effort keep-alive
            print(f'[keep-alive] ping failed: {exc}')


def _start_self_ping():
    if not KEEP_ALIVE_URL:
        return
    threading.Thread(target=_self_ping_loop,
                     name='self-ping', daemon=True).start()
    print(f'[keep-alive] self-ping every {SELF_PING_INTERVAL:.0f}s -> {KEEP_ALIVE_URL}')


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------
def main():
    _start_health_server()
    _start_self_ping()
    try:
        bot.run(TOKEN)
    finally:
        _self_ping_stop.set()
        if _health_server is not None:
            _health_server.shutdown()


if __name__ == '__main__':
    main()
