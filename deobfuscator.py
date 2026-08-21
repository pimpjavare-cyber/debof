"""
Deobfuscation engine.

Supported types:
  - Luraph 14.x  (bytecode VM pattern, current as of 2024-2026)
  - LuaU VMP     (Roblox VMP virtualization layer)
  - Luraph legacy (≤13.x string-table VM)
  - Prometheus / MoonSec V2 / V3
  - IronBrew 2

Detection runs a scored fingerprint pass over the raw source. Each processor
implements:
    process(source: str) -> str
"""

from __future__ import annotations

import base64
import re
import struct
import zlib
from enum import Enum
from typing import Optional


class DeobfError(Exception):
    pass


class ObfuscatorType(str, Enum):
    LURAPH14       = "luraph14"
    LUAUVMP        = "luauvmp"
    LURAPH_LEGACY  = "luraph_legacy"
    PROMETHEUS     = "prometheus"
    MOONSEC2       = "moonsec2"
    MOONSEC3       = "moonsec3"
    IRONBREW2      = "ironbrew2"
    UNKNOWN        = "unknown"


# ── Fingerprint signatures ────────────────────────────────────────────────────

_SIGNATURES: dict[ObfuscatorType, list[str | re.Pattern]] = {
    ObfuscatorType.LURAPH14: [
        re.compile(r'local\s+\w+\s*=\s*\{["\']LPH["\']'),        # LPH header table
        re.compile(r'--\s*Luraph\s+(?:14|1[4-9])'),               # version comment
        re.compile(r'xpcall\s*\(.*?function\s*\(\).*?end\s*,'),   # xpcall wrapper
        re.compile(r'local\s+\w+\s*=\s*["\'][A-Za-z0-9+/=]{40,}["\']'),  # b64 payload
        "LURAPH_UNIQUE_IDENTIFIER",
    ],
    ObfuscatorType.LUAUVMP: [
        re.compile(r'--\s*luau[- ]?vmp', re.IGNORECASE),
        re.compile(r'local\s+\w+\s*=\s*buffer\.create'),          # buffer API
        re.compile(r'string\.pack\s*\(\s*["\']<[BbHhIiJj]'),      # packed bytecode
        re.compile(r'bit32\.(band|bor|bxor|lshift|rshift)'),      # bit32 heavy use
        "LUAUVMP_MARKER",
    ],
    ObfuscatorType.LURAPH_LEGACY: [
        re.compile(r'--\s*Luraph\s+(?:1[0-3]|[1-9])'),
        re.compile(r'local\s+\w+\s*=\s*["\'][A-Za-z0-9+/=]{20,}["\'].*?loadstring'),
        "LURAPH_V",
    ],
    ObfuscatorType.PROMETHEUS: [
        re.compile(r'--\s*PROMETHEUS', re.IGNORECASE),
        re.compile(r'PHASE_BOUNDARY'),
        re.compile(r'local\s+\w+\s*=\s*\{\s*\[1\]\s*=\s*\d+'),
        re.compile(r'local\s+\w+\s*=\s*math\.floor'),
    ],
    ObfuscatorType.MOONSEC2: [
        re.compile(r'--\s*MoonSec\s+V?2', re.IGNORECASE),
        re.compile(r'local\s+\w+\s*=\s*\(function\(\).*?end\)\(\)', re.DOTALL),
        re.compile(r'string\.byte.*?string\.char.*?for\s+\w+\s*=\s*1'),
    ],
    ObfuscatorType.MOONSEC3: [
        re.compile(r'--\s*MoonSec\s+V?3', re.IGNORECASE),
        re.compile(r'local\s+\w+\s*=\s*["\'][A-Za-z0-9+/=]{100,}["\']'),
        re.compile(r'local\s+\w+\s*=\s*loadstring\s*\('),
        re.compile(r'local\s+\w+\s*=\s*select\s*\('),
    ],
    ObfuscatorType.IRONBREW2: [
        re.compile(r'--\s*IronBrew\s*2', re.IGNORECASE),
        re.compile(r'local\s+\w+\s*=\s*\d+\s+local\s+\w+\s*=\s*\{\}'),
        re.compile(r'Synapse\s+XEN|IB2'),
    ],
}


# ── Detection ─────────────────────────────────────────────────────────────────

def _score(source: str, patterns: list) -> int:
    score = 0
    for p in patterns:
        if isinstance(p, re.Pattern):
            if p.search(source):
                score += 2
        elif isinstance(p, str):
            if p in source:
                score += 3
    return score


# ── Base processor ────────────────────────────────────────────────────────────

class BaseProcessor:
    obf_type: ObfuscatorType

    def process(self, source: str) -> str:
        raise NotImplementedError


# ── Luraph 14.x processor ─────────────────────────────────────────────────────

class Luraph14Processor(BaseProcessor):
    """
    Luraph 14.x uses a multi-layer VM:
      1. Outer xpcall wrapper with environment isolation
      2. Base64-encoded + zlib-compressed inner bytecode payload
      3. String constant table (XOR-obfuscated keys)
      4. Custom opcode dispatch table

    This processor strips layers 1-3 and reconstructs readable Lua.
    Full bytecode lifting requires a separate Luau compiler step.
    """

    obf_type = ObfuscatorType.LURAPH14

    # Pattern: local <name> = "<base64 payload>"
    _B64_PAYLOAD = re.compile(
        r'local\s+(\w+)\s*=\s*["\']([A-Za-z0-9+/=]{40,})["\']'
    )
    # Pattern: string constant table  { "...", "...", ... }
    _STRING_TABLE = re.compile(
        r'local\s+(\w+)\s*=\s*\{([^}]{20,})\}'
    )
    # XOR key extraction from Luraph's string decoder stub
    _XOR_KEY = re.compile(
        r'for\s+\w+\s*=\s*1\s*,\s*#\w+\s+do\s+\w+\[?\w+\]?\s*=\s*'
        r'string\.char\s*\(\s*string\.byte\s*\(\s*\w+\s*,\s*\w+\s*\)\s*'
        r'%s+\s*(\d+)\s*\)',
        re.DOTALL,
    )

    def process(self, source: str) -> str:
        out = source

        # Layer 1: strip the outer xpcall environment wrapper
        out = self._strip_xpcall_wrapper(out)

        # Layer 2: decode base64 payload(s)
        out = self._decode_b64_payloads(out)

        # Layer 3: decode XOR string table
        out = self._decode_string_table(out)

        # Layer 4: rename obfuscated identifiers (heuristic)
        out = self._rename_identifiers(out)

        return out

    def _strip_xpcall_wrapper(self, source: str) -> str:
        # Luraph 14 wraps everything in:
        #   xpcall(function() ... end, function(e) end)
        # Strip the outer call, keep the inner body.
        pattern = re.compile(
            r'^xpcall\s*\(\s*function\s*\(\s*\)\s*(.*?)end\s*,\s*function.*?end\s*\)\s*$',
            re.DOTALL,
        )
        m = pattern.match(source.strip())
        if m:
            return m.group(1).strip()
        return source

    def _decode_b64_payloads(self, source: str) -> str:
        def try_decode(b64: str) -> str | None:
            try:
                raw = base64.b64decode(b64 + "==")
                # Try zlib decompress (Luraph compresses with zlib level 9)
                try:
                    return zlib.decompress(raw).decode("utf-8", errors="replace")
                except zlib.error:
                    pass
                # Raw UTF-8 fallback
                return raw.decode("utf-8", errors="replace")
            except Exception:
                return None

        def replacer(m: re.Match) -> str:
            varname, b64 = m.group(1), m.group(2)
            decoded = try_decode(b64)
            if decoded and len(decoded) > 10 and "\x00" not in decoded[:20]:
                return f"-- [deobf: decoded payload for {varname}]\n{decoded}"
            return m.group(0)

        return self._B64_PAYLOAD.sub(replacer, source)

    def _decode_string_table(self, source: str) -> str:
        # Extract XOR key if present
        xor_key = 0
        km = self._XOR_KEY.search(source)
        if km:
            try:
                xor_key = int(km.group(1))
            except ValueError:
                pass

        def decode_str(s: str) -> str:
            if xor_key == 0:
                return s
            return "".join(chr(ord(c) ^ xor_key) for c in s)

        def table_replacer(m: re.Match) -> str:
            varname, body = m.group(1), m.group(2)
            strings = re.findall(r'["\']([^"\']*)["\']', body)
            if not strings:
                return m.group(0)
            decoded_strings = [decode_str(s) for s in strings]
            readable = ", ".join(f'"{s}"' for s in decoded_strings)
            return f"local {varname} = {{{readable}}}"

        return self._STRING_TABLE.sub(table_replacer, source)

    def _rename_identifiers(self, source: str) -> str:
        # Luraph 14 uses single-char or hash-based names.
        # Replace >=6-char hex-like identifiers with readable placeholders.
        counter = [0]

        def make_name() -> str:
            counter[0] += 1
            return f"_var{counter[0]}"

        # Match identifiers that look like obfuscated hashes (all hex + underscore, ≥8 chars)
        pattern = re.compile(r'\b([0-9a-fA-F_]{8,})\b')
        seen: dict[str, str] = {}

        def replacer(m: re.Match) -> str:
            token = m.group(1)
            # Skip numeric literals
            if re.fullmatch(r'[0-9a-fA-F]+', token):
                return token
            if token not in seen:
                seen[token] = make_name()
            return seen[token]

        return pattern.sub(replacer, source)


# ── LuaU VMP processor ────────────────────────────────────────────────────────

class LuauVMPProcessor(BaseProcessor):
    """
    LuaU VMP packs bytecode into a binary string via string.pack(<format>, ...)
    and executes it through a custom Luau VM interpreter written in Luau itself.

    This processor:
      1. Extracts the packed bytecode blob
      2. Reconstructs the opcode stream into readable pseudo-Lua
      3. Strips the interpreter scaffolding
    """

    obf_type = ObfuscatorType.LUAUVMP

    _PACKED_BLOB = re.compile(
        r'local\s+(\w+)\s*=\s*string\.pack\s*\(\s*["\'](<[BbHhIiJjfd]+)["\']'
        r'\s*,(.*?)\)',
        re.DOTALL,
    )
    _BUFFER_BLOB = re.compile(
        r'local\s+(\w+)\s*=\s*buffer\.create\s*\(\s*(\d+)\s*\)',
    )
    _BIT32_CHAIN = re.compile(
        r'bit32\.(band|bor|bxor|lshift|rshift)\s*\(([^)]+)\)',
    )

    # Luau VMP opcode table (version 3 bytecode)
    # Opcodes from luau-lang/luau/blob/master/VM/include/lobject.h
    _LUAU_OPCODES = {
        0:  "NOP",      1:  "BREAK",    2:  "LOADNIL",  3:  "LOADB",
        4:  "LOADN",    5:  "LOADK",    6:  "MOVE",     7:  "GETUPVAL",
        8:  "SETUPVAL", 9:  "CLOSEUPVALS", 10: "GETIMPORT", 11: "GETTABLE",
        12: "SETTABLE", 13: "GETTABLEKS", 14: "SETTABLEKS", 15: "GETTABLEN",
        16: "SETTABLEN", 17: "NEWCLOSURE", 18: "NAMECALL", 19: "CALL",
        20: "RETURN",   21: "JUMP",     22: "JUMPBACK",  23: "JUMPIF",
        24: "JUMPIFNOT", 25: "JUMPIFEQ", 26: "JUMPIFLE", 27: "JUMPIFLT",
        28: "JUMPIFNOTEQ", 29: "JUMPIFNOTLE", 30: "JUMPIFNOTLT",
        31: "ADD",      32: "SUB",      33: "MUL",      34: "DIV",
        35: "MOD",      36: "POW",      37: "ADDK",     38: "SUBK",
        39: "MULK",     40: "DIVK",     41: "MODK",     42: "POWK",
        43: "AND",      44: "OR",       45: "ANDK",     46: "ORK",
        47: "CONCAT",   48: "NOT",      49: "MINUS",    50: "LENGTH",
        51: "NEWTABLE", 52: "DUPTABLE", 53: "SETLIST",  54: "FORNPREP",
        55: "FORNLOOP", 56: "FORGLOOP", 57: "FORGPREP_INEXT",
        58: "FORGLOOP_INEXT", 59: "FORGPREP_NEXT", 60: "FORGLOOP_NEXT",
        61: "GETVARARGS", 62: "DUPCLOSURE", 63: "PREPVARARGS",
        64: "LOADKX",   65: "JUMPX",    66: "FASTCALL", 67: "COVERAGE",
        68: "CAPTURE",  69: "FASTCALL1", 70: "FASTCALL2", 71: "FASTCALL2K",
        72: "FORGPREP", 73: "JUMPXEQKNIL", 74: "JUMPXEQKB",
        75: "JUMPXEQKN", 76: "JUMPXEQKS",
    }

    def process(self, source: str) -> str:
        out = source

        # Step 1: evaluate static bit32 chains
        out = self._fold_bit32(out)

        # Step 2: extract and disassemble bytecode blob if present
        blob_result = self._extract_bytecode(out)
        if blob_result:
            varname, disasm = blob_result
            out = re.sub(
                rf'local\s+{re.escape(varname)}\s*=.*?(?=\n\s*local|\Z)',
                f"-- [deobf: disassembly of {varname}]\n{disasm}\n",
                out,
                flags=re.DOTALL,
            )

        # Step 3: strip interpreter scaffolding
        out = self._strip_vm_scaffolding(out)

        # Step 4: clean up bit32 residue
        out = self._clean_bit32_residue(out)

        return out

    def _fold_bit32(self, source: str) -> str:
        """Constant-fold simple bit32 expressions."""
        def fold(m: re.Match) -> str:
            op, args_str = m.group(1), m.group(2)
            args = [a.strip() for a in args_str.split(",")]
            try:
                vals = [int(a) for a in args]
            except ValueError:
                return m.group(0)
            result: int
            if op == "band":
                result = vals[0] & vals[1]
            elif op == "bor":
                result = vals[0] | vals[1]
            elif op == "bxor":
                result = vals[0] ^ vals[1]
            elif op == "lshift":
                result = (vals[0] << vals[1]) & 0xFFFFFFFF
            elif op == "rshift":
                result = (vals[0] >> vals[1]) & 0xFFFFFFFF
            else:
                return m.group(0)
            return str(result)

        # Run multiple passes until no changes remain
        prev = None
        while prev != source:
            prev = source
            source = self._BIT32_CHAIN.sub(fold, source)
        return source

    def _extract_bytecode(self, source: str) -> tuple[str, str] | None:
        m = self._PACKED_BLOB.search(source)
        if not m:
            return None
        varname = m.group(1)
        fmt = m.group(2)
        args_raw = m.group(3)

        try:
            args = [int(a.strip()) for a in args_raw.split(",") if a.strip().lstrip("-").isdigit()]
            raw = struct.pack(fmt, *args)
        except (struct.error, ValueError):
            return None

        disasm = self._disassemble(raw)
        return varname, disasm

    def _disassemble(self, bytecode: bytes) -> str:
        """
        Luau bytecode format (version 3):
          [1 byte] version
          [1 byte] types version
          [varint] string table size
          ...
        This is a best-effort disassembly. Full lifting requires luauc.
        """
        if len(bytecode) < 2:
            return "-- [too short to disassemble]"

        lines: list[str] = ["-- [LuaU VMP disassembly]"]
        version = bytecode[0]
        lines.append(f"-- bytecode version: {version}")

        i = 2  # skip version + types_version
        pc = 0
        while i + 4 <= len(bytecode):
            word = struct.unpack_from("<I", bytecode, i)[0]
            opcode = word & 0xFF
            a = (word >> 8) & 0xFF
            b = (word >> 16) & 0xFF
            c = (word >> 24) & 0xFF
            d = (word >> 16) & 0xFFFF
            op_name = self._LUAU_OPCODES.get(opcode, f"OP_{opcode}")
            lines.append(f"  [{pc:04d}] {op_name:<20} A={a} B={b} C={c} D={d}")
            i += 4
            pc += 1
            if pc > 2000:
                lines.append("  ... [truncated at 2000 instructions]")
                break

        return "\n".join(lines)

    def _strip_vm_scaffolding(self, source: str) -> str:
        # Remove the interpreter loop — typically a large while true do / repeat until false block
        # that contains the opcode dispatch table
        pattern = re.compile(
            r'(?:while\s+true\s+do|repeat).*?(?:end|until\s+false)',
            re.DOTALL,
        )
        # Only strip if the block contains an opcode dispatch signature
        def strip_if_vm(m: re.Match) -> str:
            block = m.group(0)
            if "OPCODE" in block or "opcode" in block or "dispatch" in block.lower():
                return "-- [deobf: VM interpreter loop removed]"
            return block

        return pattern.sub(strip_if_vm, source)

    def _clean_bit32_residue(self, source: str) -> str:
        # Remove pure bit32 constant assignments that fold to 0 or are unused
        return re.sub(r'local\s+\w+\s*=\s*0\s*--\s*\[deobf.*?\]\n?', "", source)


# ── Prometheus / MoonSec processor ───────────────────────────────────────────

class PrometheusProcessor(BaseProcessor):
    """
    Prometheus and MoonSec V2/V3 use a shared pattern:
      - Large base64 string → zlib decompress → inner VM Lua source
      - String table with integer-indexed keys
      - loadstring() call at the bottom

    MoonSec V3 adds an extra encryption layer over the base64 blob.
    """

    obf_type = ObfuscatorType.PROMETHEUS

    _B64_VAR = re.compile(r'local\s+(\w+)\s*=\s*["\']([A-Za-z0-9+/=]{50,})["\']')
    _LOADSTRING = re.compile(r'loadstring\s*\(\s*(\w+)\s*\)')
    _INT_TABLE = re.compile(r'local\s+(\w+)\s*=\s*\{(\s*(?:\d+\s*,?\s*){5,})\}')

    def process(self, source: str) -> str:
        out = source
        out = self._decode_payloads(out)
        out = self._resolve_int_tables(out)
        out = self._strip_loadstring_wrapper(out)
        return out

    def _decode_payloads(self, source: str) -> str:
        def replacer(m: re.Match) -> str:
            varname, b64 = m.group(1), m.group(2)
            try:
                raw = base64.b64decode(b64 + "==")
                # zlib
                try:
                    decoded = zlib.decompress(raw).decode("utf-8", errors="replace")
                    return f"-- [deobf: decoded {varname}]\n{decoded}"
                except zlib.error:
                    pass
                # raw string
                decoded = raw.decode("utf-8", errors="replace")
                if decoded.count("\n") > 2:
                    return f"-- [deobf: decoded {varname}]\n{decoded}"
            except Exception:
                pass
            return m.group(0)
        return self._B64_VAR.sub(replacer, source)

    def _resolve_int_tables(self, source: str) -> str:
        def replacer(m: re.Match) -> str:
            varname, body = m.group(1), m.group(2)
            nums = re.findall(r'\d+', body)
            try:
                chars = "".join(chr(int(n)) for n in nums if int(n) < 128)
                if chars.isprintable():
                    return f'local {varname} = "{chars}" -- [deobf: int table resolved]'
            except (ValueError, OverflowError):
                pass
            return m.group(0)
        return self._INT_TABLE.sub(replacer, source)

    def _strip_loadstring_wrapper(self, source: str) -> str:
        # Replace loadstring(var) calls with a comment when the var has been decoded
        return self._LOADSTRING.sub(
            lambda m: f"-- [deobf: loadstring({m.group(1)}) — decoded above]",
            source,
        )


class MoonSec2Processor(PrometheusProcessor):
    obf_type = ObfuscatorType.MOONSEC2


class MoonSec3Processor(PrometheusProcessor):
    obf_type = ObfuscatorType.MOONSEC3

    def process(self, source: str) -> str:
        # MoonSec V3 has an additional XOR layer before base64
        out = self._peel_xor_layer(source)
        return super().process(out)

    def _peel_xor_layer(self, source: str) -> str:
        # MoonSec V3 XOR key is extracted from the select() call
        key_m = re.search(r'select\s*\(\s*(\d+)\s*,', source)
        if not key_m:
            return source
        xor_key = int(key_m.group(1)) & 0xFF

        def xor_strings(m: re.Match) -> str:
            s = m.group(1)
            decoded = "".join(chr(ord(c) ^ xor_key) for c in s)
            if decoded.isascii():
                return f'"{decoded}"'
            return m.group(0)

        return re.sub(r'"([^"]{10,})"', xor_strings, source)


# ── IronBrew 2 processor ──────────────────────────────────────────────────────

class IronBrew2Processor(BaseProcessor):
    obf_type = ObfuscatorType.IRONBREW2

    _STRTABLE = re.compile(r'\{([^}]{50,})\}')

    def process(self, source: str) -> str:
        out = source
        out = self._decode_string_chunks(out)
        out = self._strip_ib2_header(out)
        return out

    def _decode_string_chunks(self, source: str) -> str:
        def replacer(m: re.Match) -> str:
            body = m.group(1)
            nums = re.findall(r'\d+', body)
            if len(nums) < 5:
                return m.group(0)
            try:
                chars = "".join(chr(int(n)) for n in nums if int(n) < 256)
                if sum(c.isprintable() for c in chars) / max(len(chars), 1) > 0.75:
                    return f'"{chars}"'
            except (ValueError, OverflowError):
                pass
            return m.group(0)
        return self._STRTABLE.sub(replacer, source)

    def _strip_ib2_header(self, source: str) -> str:
        return re.sub(
            r'--\s*IronBrew\s*2.*?\n',
            "-- [deobf: IronBrew 2 header removed]\n",
            source,
            flags=re.IGNORECASE,
        )


# ── Luraph legacy processor ───────────────────────────────────────────────────

class LuraphLegacyProcessor(BaseProcessor):
    obf_type = ObfuscatorType.LURAPH_LEGACY

    _B64 = re.compile(r'["\']([A-Za-z0-9+/=]{30,})["\']')

    def process(self, source: str) -> str:
        def replacer(m: re.Match) -> str:
            b64 = m.group(1)
            try:
                raw = base64.b64decode(b64 + "==")
                decoded = zlib.decompress(raw).decode("utf-8", errors="replace")
                return f"--[[ deobf ]]\n{decoded}"
            except Exception:
                try:
                    decoded = base64.b64decode(b64 + "==").decode("utf-8", errors="replace")
                    if decoded.count("\n") > 1:
                        return f"--[[ deobf ]]\n{decoded}"
                except Exception:
                    pass
            return m.group(0)
        return self._B64.sub(replacer, source)


# ── Engine ────────────────────────────────────────────────────────────────────

_PROCESSORS: dict[ObfuscatorType, BaseProcessor] = {
    ObfuscatorType.LURAPH14:      Luraph14Processor(),
    ObfuscatorType.LUAUVMP:       LuauVMPProcessor(),
    ObfuscatorType.LURAPH_LEGACY: LuraphLegacyProcessor(),
    ObfuscatorType.PROMETHEUS:    PrometheusProcessor(),
    ObfuscatorType.MOONSEC2:      MoonSec2Processor(),
    ObfuscatorType.MOONSEC3:      MoonSec3Processor(),
    ObfuscatorType.IRONBREW2:     IronBrew2Processor(),
}


class DeobfuscatorEngine:

    def detect(self, source: str) -> tuple[ObfuscatorType, float]:
        scores: dict[ObfuscatorType, int] = {}
        for obf_type, patterns in _SIGNATURES.items():
            scores[obf_type] = _score(source, patterns)

        best_type = max(scores, key=lambda t: scores[t])
        best_score = scores[best_type]

        max_possible = max(
            sum(2 if isinstance(p, re.Pattern) else 3 for p in pats)
            for pats in _SIGNATURES.values()
        )
        confidence = min(best_score / max(max_possible, 1), 1.0)

        if best_score == 0:
            return ObfuscatorType.UNKNOWN, 0.0
        return best_type, confidence

    def deobfuscate(
        self,
        source: str,
        hint: ObfuscatorType | None = None,
    ) -> tuple[str, ObfuscatorType]:
        if hint is not None and hint != ObfuscatorType.UNKNOWN:
            obf_type = hint
        else:
            obf_type, confidence = self.detect(source)
            if obf_type == ObfuscatorType.UNKNOWN or confidence < 0.1:
                raise DeobfError(
                    "Could not detect obfuscator type. "
                    "Try specifying the type manually with the `obfuscator` option."
                )

        processor = _PROCESSORS.get(obf_type)
        if processor is None:
            raise DeobfError(f"No processor implemented for {obf_type.value}.")

        try:
            result = processor.process(source)
        except Exception as e:
            raise DeobfError(f"Processor error ({obf_type.value}): {e}") from e

        if not result or result.strip() == source.strip():
            raise DeobfError(
                f"Processor ran but produced no changes. "
                f"The script may use a non-standard variant of {obf_type.value}."
            )

        return result, obf_type
