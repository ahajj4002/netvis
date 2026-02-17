#!/usr/bin/env python3
"""IoT protocol enumeration techniques (NIP extensions).

Implements:
- iot.mqtt_enum
- iot.coap_discovery

Default-credential checks are intentionally not implemented.
"""

from __future__ import annotations

import argparse
import random
import socket
import time
from typing import Dict, List, Tuple

from toolkit.utils import ensure_private_target, new_session_id, utc_now_iso, write_json_log


# ------------------------------
# MQTT minimal client
# ------------------------------

def _mqtt_encode_varint(n: int) -> bytes:
    out = bytearray()
    x = int(max(0, n))
    while True:
        digit = x % 128
        x //= 128
        if x > 0:
            digit |= 0x80
        out.append(digit)
        if x == 0:
            break
    return bytes(out)


def _mqtt_decode_varint(data: bytes, off: int = 0) -> Tuple[int, int]:
    mul = 1
    val = 0
    pos = int(off)
    for _ in range(4):
        if pos >= len(data):
            break
        digit = data[pos]
        pos += 1
        val += (digit & 0x7F) * mul
        if (digit & 0x80) == 0:
            return val, pos
        mul *= 128
    return val, pos


def _mqtt_connect_packet(client_id: str, keepalive: int = 30) -> bytes:
    cid = client_id.encode("utf-8", errors="ignore")
    vh = b"\x00\x04MQTT" + b"\x04" + b"\x02" + keepalive.to_bytes(2, "big")  # clean session
    pl = len(cid).to_bytes(2, "big") + cid
    rem = _mqtt_encode_varint(len(vh) + len(pl))
    return b"\x10" + rem + vh + pl


def _mqtt_subscribe_packet(packet_id: int, topic: str, qos: int = 0) -> bytes:
    t = topic.encode("utf-8", errors="ignore")
    vh = int(packet_id).to_bytes(2, "big")
    pl = len(t).to_bytes(2, "big") + t + bytes([int(qos) & 0x03])
    rem = _mqtt_encode_varint(len(vh) + len(pl))
    return b"\x82" + rem + vh + pl


def _mqtt_parse_publish(packet: bytes) -> Dict[str, object]:
    if not packet:
        return {}
    fixed = packet[0]
    ptype = (fixed >> 4) & 0x0F
    if ptype != 3:  # PUBLISH
        return {}
    rem_len, pos = _mqtt_decode_varint(packet, 1)
    end = min(len(packet), pos + rem_len)
    if pos + 2 > end:
        return {}
    topic_len = int.from_bytes(packet[pos : pos + 2], "big")
    pos += 2
    if pos + topic_len > end:
        return {}
    topic = packet[pos : pos + topic_len].decode("utf-8", errors="ignore")
    pos += topic_len
    qos = (fixed >> 1) & 0x03
    if qos > 0:
        if pos + 2 > end:
            return {}
        pos += 2  # packet id
    payload = packet[pos:end]
    return {"topic": topic, "payload": payload.decode("utf-8", errors="ignore"), "payload_len": len(payload), "qos": int(qos)}


def mqtt_enum(target: str, *, port: int = 1883, duration: int = 8, subscribe_topic: str = "#") -> Dict[str, object]:
    ensure_private_target(target)
    started_at = utc_now_iso()
    start = time.time()

    out = {
        "technique": "mqtt_enum",
        "target": str(target),
        "port": int(port),
        "started_at": started_at,
        "scan_duration_seconds": 0.0,
        "connected": False,
        "connack_code": None,
        "topics": [],
        "messages_sample": [],
        "message_count": 0,
        "notes": "",
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3.0)
    try:
        sock.connect((str(target), int(port)))
    except Exception as e:
        out["notes"] = f"connect_failed: {e}"
        out["scan_duration_seconds"] = max(0.0001, time.time() - start)
        try:
            sock.close()
        except Exception:
            pass
        return out

    try:
        cid = f"netvis-{random.randint(1000,9999)}"
        sock.sendall(_mqtt_connect_packet(cid))
        # Expect CONNACK: 0x20 0x02 ackFlags returnCode
        resp = sock.recv(4)
        if len(resp) >= 4 and resp[0] == 0x20:
            out["connected"] = True
            out["connack_code"] = int(resp[3])
        if not out["connected"] or int(out["connack_code"] or 255) != 0:
            out["notes"] = f"connack_rejected(code={out['connack_code']})"
            out["scan_duration_seconds"] = max(0.0001, time.time() - start)
            try:
                sock.close()
            except Exception:
                pass
            return out

        # Subscribe to wildcard.
        sock.sendall(_mqtt_subscribe_packet(1, subscribe_topic, qos=0))
        # Read SUBACK (ignore if not received quickly).
        sock.settimeout(1.0)
        try:
            _ = sock.recv(8)
        except Exception:
            pass

        # Collect published messages.
        topics = set()
        messages = []
        end = time.time() + max(1, int(duration))
        sock.settimeout(0.5)
        while time.time() < end:
            try:
                chunk = sock.recv(8192)
            except socket.timeout:
                continue
            except Exception:
                break
            if not chunk:
                break
            # Packet boundaries can be coalesced; best-effort parse first frame.
            msg = _mqtt_parse_publish(chunk)
            if msg:
                t = str(msg.get("topic") or "")
                if t:
                    topics.add(t)
                messages.append(msg)

        out["topics"] = sorted(list(topics))
        out["messages_sample"] = messages[:100]
        out["message_count"] = len(messages)
    except Exception as e:
        out["notes"] = f"mqtt_error: {e}"
    finally:
        try:
            sock.close()
        except Exception:
            pass

    out["scan_duration_seconds"] = max(0.0001, time.time() - start)
    return out


# ------------------------------
# CoAP discovery
# ------------------------------

def _coap_encode_option(delta: int, length: int) -> bytes:
    # Supports only small values (<13) for this lab use.
    if delta >= 13 or length >= 13:
        raise ValueError("coap option delta/length too large for simple encoder")
    return bytes([(delta << 4) | length])


def _coap_build_get_well_known_core(msg_id: int) -> bytes:
    # Header: ver=1,type=CON(0),tkl=0 => 0x40 ; code=GET(0.01)=0x01 ; msgid
    hdr = bytes([0x40, 0x01]) + int(msg_id).to_bytes(2, "big")
    # Options: Uri-Path ".well-known" (opt 11), then Uri-Path "core" (delta 0)
    opt1 = _coap_encode_option(11, len(".well-known")) + b".well-known"
    opt2 = _coap_encode_option(0, len("core")) + b"core"
    return hdr + opt1 + opt2


def coap_discovery(target: str, *, port: int = 5683, timeout: float = 2.0) -> Dict[str, object]:
    ensure_private_target(target)
    started_at = utc_now_iso()
    start = time.time()

    out = {
        "technique": "coap_discovery",
        "target": str(target),
        "port": int(port),
        "started_at": started_at,
        "scan_duration_seconds": 0.0,
        "responded": False,
        "code": "",
        "resources_raw": "",
        "resources": [],
        "notes": "",
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(max(0.5, float(timeout)))
    try:
        mid = random.randint(1, 65535)
        req = _coap_build_get_well_known_core(mid)
        sock.sendto(req, (str(target), int(port)))
        data, _addr = sock.recvfrom(8192)
        if not data or len(data) < 4:
            out["notes"] = "short_response"
        else:
            out["responded"] = True
            # Code byte at index 1: class.detail encoded as c*32+d
            code = data[1]
            out["code"] = f"{code >> 5}.{code & 0x1F:02d}"
            payload = b""
            if b"\xFF" in data:
                payload = data.split(b"\xFF", 1)[1]
            text = payload.decode("utf-8", errors="ignore").strip()
            out["resources_raw"] = text[:2000]
            # Parse comma-separated CoRE links: </sensors/temp>;rt="temperature-c"
            resources = []
            for part in text.split(","):
                part = part.strip()
                if not part:
                    continue
                resources.append({"link": part[:300]})
            out["resources"] = resources[:200]
    except Exception as e:
        out["notes"] = str(e)
    finally:
        try:
            sock.close()
        except Exception:
            pass

    out["scan_duration_seconds"] = max(0.0001, time.time() - start)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="IoT protocol enumeration")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("mqtt-enum")
    p1.add_argument("--target", required=True)
    p1.add_argument("--port", type=int, default=1883)
    p1.add_argument("--duration", type=int, default=8)

    p2 = sub.add_parser("coap-discover")
    p2.add_argument("--target", required=True)
    p2.add_argument("--port", type=int, default=5683)
    p2.add_argument("--timeout", type=float, default=2.0)

    args = parser.parse_args()
    if args.cmd == "mqtt-enum":
        result = mqtt_enum(args.target, port=int(args.port), duration=int(args.duration))
        sid = new_session_id("iot-mqtt")
    elif args.cmd == "coap-discover":
        result = coap_discovery(args.target, port=int(args.port), timeout=float(args.timeout))
        sid = new_session_id("iot-coap")
    else:
        raise SystemExit(2)

    write_json_log("iot", sid, {"result": result})
    print(sid)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

