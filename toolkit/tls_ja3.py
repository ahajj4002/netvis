#!/usr/bin/env python3
"""TLS ClientHello/ServerHello parsing helpers (JA3/JA3S + SNI/ALPN).

This file intentionally implements a minimal, dependency-free TLS handshake parser:
- It only parses a single TLS record from a single TCP payload (no TCP reassembly).
- It is good enough for common lab captures where ClientHello fits in one segment.

Used by:
- tls/ techniques (JA3/JA3S)
- dns/ advanced techniques (DoH/DoT detection via SNI on 443/853)
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


# RFC 8701 GREASE values.
_GREASE_VALUES = {
    0x0A0A,
    0x1A1A,
    0x2A2A,
    0x3A3A,
    0x4A4A,
    0x5A5A,
    0x6A6A,
    0x7A7A,
    0x8A8A,
    0x9A9A,
    0xAAAA,
    0xBABA,
    0xCACA,
    0xDADA,
    0xEAEA,
    0xFAFA,
}


def _is_grease(v: int) -> bool:
    return int(v) in _GREASE_VALUES


def _md5_hex(s: str) -> str:
    return hashlib.md5(s.encode("utf-8", errors="ignore")).hexdigest()


def _read_u8(data: bytes, off: int) -> Tuple[int, int]:
    return data[off], off + 1


def _read_u16(data: bytes, off: int) -> Tuple[int, int]:
    return int.from_bytes(data[off : off + 2], "big"), off + 2


def _read_u24(data: bytes, off: int) -> Tuple[int, int]:
    return int.from_bytes(data[off : off + 3], "big"), off + 3


def _read_bytes(data: bytes, off: int, n: int) -> Tuple[bytes, int]:
    return data[off : off + n], off + n


@dataclass
class ClientHelloInfo:
    version: int
    ciphers: List[int]
    extensions: List[int]
    groups: List[int]
    ec_point_formats: List[int]
    sni: str = ""
    alpn: List[str] = None

    def ja3_string(self) -> str:
        cs = "-".join(str(x) for x in self.ciphers)
        ex = "-".join(str(x) for x in self.extensions)
        gr = "-".join(str(x) for x in self.groups)
        pf = "-".join(str(x) for x in self.ec_point_formats)
        return f"{self.version},{cs},{ex},{gr},{pf}"

    def ja3_hash(self) -> str:
        return _md5_hex(self.ja3_string())


@dataclass
class ServerHelloInfo:
    version: int
    cipher: int
    extensions: List[int]

    def ja3s_string(self) -> str:
        ex = "-".join(str(x) for x in self.extensions)
        return f"{self.version},{self.cipher},{ex}"

    def ja3s_hash(self) -> str:
        return _md5_hex(self.ja3s_string())


def _parse_tls_record(data: bytes) -> Optional[Tuple[int, int, bytes]]:
    """Return (content_type, version, fragment) for the first TLS record in data."""
    if not data or len(data) < 5:
        return None
    content_type = data[0]
    version = int.from_bytes(data[1:3], "big")
    length = int.from_bytes(data[3:5], "big")
    if length < 0 or (5 + length) > len(data):
        return None
    fragment = data[5 : 5 + length]
    return content_type, version, fragment


def _parse_sni(ext_data: bytes) -> str:
    # RFC 6066: server_name extension
    try:
        off = 0
        list_len, off = _read_u16(ext_data, off)
        end = min(len(ext_data), off + list_len)
        while off + 3 <= end:
            name_type, off = _read_u8(ext_data, off)
            name_len, off = _read_u16(ext_data, off)
            name_bytes, off = _read_bytes(ext_data, off, name_len)
            if name_type == 0:
                return name_bytes.decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""
    return ""


def _parse_alpn(ext_data: bytes) -> List[str]:
    # RFC 7301: ALPN extension
    out: List[str] = []
    try:
        off = 0
        list_len, off = _read_u16(ext_data, off)
        end = min(len(ext_data), off + list_len)
        while off + 1 <= end:
            ln, off = _read_u8(ext_data, off)
            if ln <= 0 or off + ln > end:
                break
            b, off = _read_bytes(ext_data, off, ln)
            s = b.decode("utf-8", errors="ignore").strip()
            if s:
                out.append(s)
    except Exception:
        return out
    return out


def parse_client_hello(tcp_payload: bytes) -> Optional[ClientHelloInfo]:
    """Parse a TLS ClientHello from a single TCP payload."""
    rec = _parse_tls_record(tcp_payload or b"")
    if not rec:
        return None
    content_type, _record_version, fragment = rec
    if content_type != 22:  # handshake
        return None
    if len(fragment) < 4:
        return None
    hs_type = fragment[0]
    hs_len = int.from_bytes(fragment[1:4], "big")
    if hs_type != 1:  # ClientHello
        return None
    if 4 + hs_len > len(fragment):
        return None

    body = fragment[4 : 4 + hs_len]
    off = 0

    try:
        version, off = _read_u16(body, off)
        _random, off = _read_bytes(body, off, 32)
        sid_len, off = _read_u8(body, off)
        _sid, off = _read_bytes(body, off, int(sid_len))
        cs_len, off = _read_u16(body, off)
        cs_bytes, off = _read_bytes(body, off, int(cs_len))
        ciphers = []
        for i in range(0, len(cs_bytes), 2):
            if i + 2 > len(cs_bytes):
                break
            v = int.from_bytes(cs_bytes[i : i + 2], "big")
            if not _is_grease(v):
                ciphers.append(v)

        comp_len, off = _read_u8(body, off)
        _comp, off = _read_bytes(body, off, int(comp_len))

        extensions: List[int] = []
        groups: List[int] = []
        pfs: List[int] = []
        sni = ""
        alpn: List[str] = []

        if off + 2 <= len(body):
            ext_total_len, off = _read_u16(body, off)
            ext_end = min(len(body), off + int(ext_total_len))
            while off + 4 <= ext_end:
                ext_type, off = _read_u16(body, off)
                ext_len, off = _read_u16(body, off)
                ext_data, off = _read_bytes(body, off, int(ext_len))

                if not _is_grease(ext_type):
                    extensions.append(ext_type)

                if ext_type == 0 and not sni:
                    sni = _parse_sni(ext_data)
                elif ext_type == 16:
                    alpn = _parse_alpn(ext_data)
                elif ext_type == 10:
                    # supported_groups
                    try:
                        g_off = 0
                        g_len, g_off = _read_u16(ext_data, g_off)
                        g_end = min(len(ext_data), g_off + int(g_len))
                        while g_off + 2 <= g_end:
                            g, g_off = _read_u16(ext_data, g_off)
                            if not _is_grease(g):
                                groups.append(g)
                    except Exception:
                        pass
                elif ext_type == 11:
                    # ec_point_formats
                    try:
                        pf_off = 0
                        pf_len, pf_off = _read_u8(ext_data, pf_off)
                        pf_end = min(len(ext_data), pf_off + int(pf_len))
                        while pf_off < pf_end:
                            pf, pf_off = _read_u8(ext_data, pf_off)
                            pfs.append(int(pf))
                    except Exception:
                        pass

        return ClientHelloInfo(
            version=int(version),
            ciphers=ciphers,
            extensions=extensions,
            groups=groups,
            ec_point_formats=pfs,
            sni=sni,
            alpn=alpn,
        )
    except Exception:
        return None


def parse_server_hello(tcp_payload: bytes) -> Optional[ServerHelloInfo]:
    """Parse a TLS ServerHello from a single TCP payload."""
    rec = _parse_tls_record(tcp_payload or b"")
    if not rec:
        return None
    content_type, _record_version, fragment = rec
    if content_type != 22:
        return None
    if len(fragment) < 4:
        return None
    hs_type = fragment[0]
    hs_len = int.from_bytes(fragment[1:4], "big")
    if hs_type != 2:  # ServerHello
        return None
    if 4 + hs_len > len(fragment):
        return None

    body = fragment[4 : 4 + hs_len]
    off = 0
    try:
        version, off = _read_u16(body, off)
        _random, off = _read_bytes(body, off, 32)
        sid_len, off = _read_u8(body, off)
        _sid, off = _read_bytes(body, off, int(sid_len))
        cipher, off = _read_u16(body, off)
        _comp, off = _read_u8(body, off)

        extensions: List[int] = []
        if off + 2 <= len(body):
            ext_total_len, off = _read_u16(body, off)
            ext_end = min(len(body), off + int(ext_total_len))
            while off + 4 <= ext_end:
                ext_type, off = _read_u16(body, off)
                ext_len, off = _read_u16(body, off)
                _ext_data, off = _read_bytes(body, off, int(ext_len))
                if not _is_grease(ext_type):
                    extensions.append(ext_type)

        return ServerHelloInfo(version=int(version), cipher=int(cipher), extensions=extensions)
    except Exception:
        return None


def ja3_from_client_hello(tcp_payload: bytes) -> Optional[Dict[str, object]]:
    info = parse_client_hello(tcp_payload)
    if not info:
        return None
    return {
        "ja3": info.ja3_hash(),
        "ja3_string": info.ja3_string(),
        "version": info.version,
        "sni": info.sni,
        "alpn": list(info.alpn or []),
        "ciphers": list(info.ciphers),
        "extensions": list(info.extensions),
        "groups": list(info.groups),
        "ec_point_formats": list(info.ec_point_formats),
    }


def ja3s_from_server_hello(tcp_payload: bytes) -> Optional[Dict[str, object]]:
    info = parse_server_hello(tcp_payload)
    if not info:
        return None
    return {
        "ja3s": info.ja3s_hash(),
        "ja3s_string": info.ja3s_string(),
        "version": info.version,
        "cipher": info.cipher,
        "extensions": list(info.extensions),
    }

