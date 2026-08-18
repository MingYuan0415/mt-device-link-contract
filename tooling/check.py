from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = ROOT / "protocol.yaml"
VECTORS_PATH = ROOT / "vectors" / "golden.json"
HEX_RE = re.compile(r"^[0-9a-f]*$")


class ContractError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def load_protocol() -> dict[str, Any]:
    value = yaml.safe_load(PROTOCOL_PATH.read_text(encoding="utf-8"))
    require(isinstance(value, dict), "protocol root must be a mapping")
    return value


def _check_uuid(value: str, label: str) -> None:
    require(isinstance(value, str) and re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        value,
    ), f"invalid UUID: {label}")


def validate_protocol(protocol: dict[str, Any]) -> None:
    require(protocol.get("schema_version") == 1, "schema_version must be 1")
    data = protocol.get("protocol")
    require(isinstance(data, dict), "protocol section is required")
    require(data.get("major") == 3 and data.get("minor") == 0,
            "only Device Link v3.0 is supported")
    require(data.get("byte_order") == "little", "wire must be little endian")
    _check_uuid(data["service_uuid"], "service")
    characteristics = data.get("characteristics")
    require(set(characteristics) == {"command_rx", "event_tx"},
            "exactly command_rx and event_tx characteristics are required")
    for name, expected_property in (("command_rx", "write"), ("event_tx", "notify")):
        item = characteristics[name]
        _check_uuid(item["uuid"], name)
        require(item.get("properties") == [expected_property],
                f"{name} property mismatch")
        require(item.get("max_value_bytes") == 244,
                f"{name} max value must be 244 bytes")

    security = data.get("security")
    require(security == {
        "transport": "ble_le_secure_connections",
        "sc_only": True,
        "mitm": True,
        "bonding": False,
        "pairing_window": "physical_confirmation",
        "characteristic_requires_encrypted_authenticated_link": True,
    }, "security policy changed")

    transport = data.get("transport")
    require(transport["request_header_bytes"] == 3 and
            transport["response_header_bytes"] == 4,
            "header sizes changed")
    require(transport["request_header"] == ["version", "opcode", "sequence"],
            "request header changed")
    require(transport["response_header"] ==
            ["version", "opcode", "sequence", "status"],
            "response header changed")
    require(transport["minimum_att_mtu"] == 247 and
            transport["maximum_value_bytes"] == 244 and
            transport["fragmented_messages"] is False and
            transport["one_outstanding_request"] is True,
            "transport limits changed")

    statuses = protocol.get("status_codes")
    require(statuses == {
        "OK": 0,
        "ACCEPTED": 1,
        "BUSY": 2,
        "INVALID_ARGUMENT": 3,
        "NOT_FOUND": 4,
        "UNAVAILABLE": 5,
        "STORAGE": 6,
        "INTERNAL": 7,
        "UNSUPPORTED": 8,
    }, "status registry changed")

    commands = protocol.get("commands")
    require(isinstance(commands, list) and len(commands) == 9,
            "the nine v3 commands are required")
    ids = [item.get("id") for item in commands]
    names = [item.get("name") for item in commands]
    require(ids == list(range(1, 10)), "command IDs must be 1..9")
    require(names == [
        "GET_INFO", "GET_STATUS", "START_SCAN", "GET_SCAN_PAGE",
        "SET_CREDENTIALS", "CONNECT", "DISCONNECT", "FORGET",
        "SET_AUTO_CONNECT",
    ], "command table changed")
    for item in commands:
        require(isinstance(item.get("request"), list) and
                isinstance(item.get("response"), list),
                f"invalid command layout: {item.get('name')}")
        if item["name"] in {"START_SCAN", "SET_CREDENTIALS", "CONNECT",
                             "DISCONNECT", "FORGET", "SET_AUTO_CONNECT"}:
            require(item.get("asynchronous") is True,
                    f"{item['name']} must be asynchronous")
        else:
            require(item.get("asynchronous") is False,
                    f"{item['name']} must be synchronous")

    events = protocol.get("events")
    require(events == [{
        "id": 240,
        "name": "WIFI_STATUS",
        "payload": [
            "wifi_state:enum_u8(wifi_state)",
            "failure:enum_u8(wifi_failure)",
            "ssid:bytes_u8",
            "has_ipv4:bool",
            "profile_persisted:bool",
            "auto_connect:bool",
            "revision:u32",
        ],
    }], "event table changed")


def _status_value(protocol: dict[str, Any], status: str | None) -> int:
    if status is None:
        return 0
    statuses = protocol["status_codes"]
    require(status in statuses, f"unknown status in vector: {status}")
    return statuses[status]


def validate_vector(protocol: dict[str, Any], case: dict[str, Any]) -> None:
    require(set(case) == {"id", "kind", "opcode", "sequence", "status", "hex"},
            f"vector keys changed: {case.get('id')}")
    raw_hex = case["hex"]
    require(isinstance(raw_hex, str) and len(raw_hex) % 2 == 0 and
            HEX_RE.fullmatch(raw_hex) is not None,
            f"invalid vector hex: {case['id']}")
    raw = bytes.fromhex(raw_hex)
    kind = case["kind"]
    require(kind in {"request", "response", "event"},
            f"invalid vector kind: {case['id']}")
    require(0 <= case["opcode"] <= 255 and 0 <= case["sequence"] <= 255,
            f"vector header range: {case['id']}")
    require(len(raw) <= 244, f"vector exceeds ATT value budget: {case['id']}")
    if kind == "request":
        require(len(raw) >= 3 and raw[:3] == bytes((3, case["opcode"], case["sequence"])),
                f"request header mismatch: {case['id']}")
        require(case["status"] is None, f"request status must be null: {case['id']}")
    else:
        require(len(raw) >= 4 and raw[:4] == bytes((3, case["opcode"], case["sequence"],
                                                      _status_value(protocol, case["status"]))),
                f"response/event header mismatch: {case['id']}")
        if kind == "event":
            require(case["sequence"] == 0 and case["opcode"] == 240,
                    f"event identity mismatch: {case['id']}")


def validate_vectors(protocol: dict[str, Any]) -> None:
    vectors = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    require(vectors.get("protocol") == "device-link/v3", "vector protocol mismatch")
    cases = vectors.get("cases")
    require(isinstance(cases, list) and len(cases) == 10, "vector coverage changed")
    ids = [case.get("id") for case in cases]
    require(len(ids) == len(set(ids)), "duplicate vector IDs")
    for case in cases:
        validate_vector(protocol, case)


def normalized_digest(protocol: dict[str, Any]) -> str:
    encoded = json.dumps(protocol, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def main() -> int:
    protocol = load_protocol()
    validate_protocol(protocol)
    validate_vectors(protocol)
    print("Device Link v3 contract verified")
    print(f"schema_digest={normalized_digest(protocol)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
