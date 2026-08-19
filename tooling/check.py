from __future__ import annotations

import argparse
import hashlib
import json
import re
import unicodedata
import uuid
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = ROOT / "protocol.yaml"
VECTORS_PATH = ROOT / "vectors" / "golden.json"
VERSION_PATH = ROOT / "VERSION"
HEX_RE = re.compile(r"^[0-9a-f]*$")


class ContractError(ValueError):
    """A stable validation failure exposed to vectors and tests."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code


def fail(code: str, message: str) -> None:
    raise ContractError(code, message)


def require(condition: bool, code: str, message: str) -> None:
    if not condition:
        fail(code, message)


def _same_typed(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if type(actual) is dict:
        return (actual.keys() == expected.keys() and
                all(_same_typed(actual[key], expected[key]) for key in actual))
    if type(actual) is list:
        return (len(actual) == len(expected) and
                all(_same_typed(left, right)
                    for left, right in zip(actual, expected)))
    return actual == expected


def _require_exact(actual: Any, expected: Any, code: str,
                   message: str) -> None:
    require(_same_typed(actual, expected), code, message)


def _is_int(value: Any) -> bool:
    return type(value) is int


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(loader: _UniqueKeyLoader, node: yaml.Node,
                              deep: bool = False) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise ContractError(
                "TYPE", "YAML mapping keys must be hashable"
            ) from exc
        if duplicate:
            fail("DUPLICATE_KEY", f"duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail("DUPLICATE_KEY", f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    fail("LOAD", f"non-standard JSON constant: {value}")


def load_protocol(path: Path = PROTOCOL_PATH) -> dict[str, Any]:
    try:
        value = yaml.load(path.read_text(encoding="utf-8"),
                          Loader=_UniqueKeyLoader)
    except ContractError:
        raise
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ContractError("LOAD", f"cannot load protocol: {exc}") from exc
    require(type(value) is dict, "TYPE", "protocol root must be a mapping")
    return value


def load_vectors(path: Path = VECTORS_PATH) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except ContractError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContractError("LOAD", f"cannot load vectors: {exc}") from exc
    require(type(value) is dict, "TYPE", "vectors root must be a mapping")
    return value


def _mapping(value: Any, required: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict, "TYPE", f"{label} must be a mapping")
    require(all(type(key) is str for key in value), "TYPE",
            f"{label} keys must be strings")
    actual = set(value)
    missing = required - actual
    unknown = actual - required
    require(not missing, "MISSING_FIELD",
            f"{label} missing fields: {sorted(missing)}")
    require(not unknown, "UNKNOWN_FIELD",
            f"{label} unknown fields: {sorted(unknown)}")
    return value


def _list(value: Any, label: str, nonempty: bool = False) -> list[Any]:
    require(type(value) is list, "TYPE", f"{label} must be a list")
    require(not nonempty or bool(value), "LENGTH", f"{label} must not be empty")
    return value


def _string(value: Any, label: str) -> str:
    require(type(value) is str and bool(value), "TYPE",
            f"{label} must be a non-empty string")
    return value


def _integer(value: Any, label: str, minimum: int | None = None,
             maximum: int | None = None) -> int:
    require(_is_int(value), "TYPE", f"{label} must be an integer")
    if minimum is not None:
        require(value >= minimum, "VALUE", f"{label} is below {minimum}")
    if maximum is not None:
        require(value <= maximum, "VALUE", f"{label} exceeds {maximum}")
    return value


def _boolean(value: Any, label: str) -> bool:
    require(type(value) is bool, "TYPE", f"{label} must be boolean")
    return value


def _hex(value: Any, label: str) -> bytes:
    require(type(value) is str and len(value) % 2 == 0 and
            HEX_RE.fullmatch(value) is not None,
            "HEX", f"{label} must be lowercase even-length hex")
    return bytes.fromhex(value)


def _validate_uuid(text: Any, octets: Any, label: str) -> None:
    value = _string(text, f"{label}.uuid")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ContractError("UUID", f"invalid UUID: {label}") from exc
    require(str(parsed) == value, "UUID", f"{label} UUID must be canonical lowercase")
    raw = _hex(octets, f"{label}.att_octets")
    require(len(raw) == 16, "UUID", f"{label} ATT UUID must be 16 bytes")
    require(raw == parsed.bytes[::-1], "UUID",
            f"{label} ATT UUID octet order is incorrect")


def _validate_enum(value: Any, expected: dict[str, int], label: str) -> None:
    mapping = _mapping(value, set(expected), label)
    for name, number in mapping.items():
        _integer(number, f"{label}.{name}", 0, 255)
    require(mapping == expected, "VALUE", f"{label} assignments changed")
    require(len(set(mapping.values())) == len(mapping), "VALUE",
            f"{label} values must be unique")


def _enum_mapping(value: Any, names: set[str], label: str) -> dict[str, int]:
    mapping = _mapping(value, names, label)
    for name, number in mapping.items():
        _integer(number, f"{label}.{name}", 0, 255)
    require(len(set(mapping.values())) == len(mapping), "VALUE",
            f"{label} values must be unique")
    return mapping


def _validate_wire_types(value: Any) -> None:
    expected = {
        "u8": {"size_bytes": 1, "encoding": "unsigned"},
        "u16": {
            "size_bytes": 2, "encoding": "unsigned", "byte_order": "little",
        },
        "i8": {"size_bytes": 1, "encoding": "twos_complement"},
        "bool": {"size_bytes": 1, "false_value": 0, "true_value": 1},
        "enum_u8": {"base": "u8"},
        "bytes_u8": {"length_prefix": "u8", "length_unit": "octets"},
        "repeated": {
            "count_source": "named_prior_u8_field",
            "item_encoding": "concatenated",
        },
    }
    definitions = _mapping(value, set(expected), "wire_types")
    for name, definition in expected.items():
        actual = _mapping(definitions[name], set(definition),
                          f"wire_types.{name}")
        _require_exact(actual, definition, "VALUE",
                       f"wire_types.{name} encoding changed")


def _field_keys(wire: Any, label: str) -> set[str]:
    require(type(wire) is str, "TYPE", f"{label}.wire must be a string")
    if wire in {"u8", "u16", "bool"}:
        return {"name", "wire"}
    if wire == "enum_u8":
        return {"name", "wire", "enum"}
    if wire in {"bytes_u8", "i8"}:
        return {"name", "wire", "min_bytes", "max_bytes"} if wire == "bytes_u8" else {
            "name", "wire", "min", "max",
        }
    if wire == "repeated":
        return {"name", "wire", "item_type", "count_field"}
    fail("WIRE_TYPE", f"unknown wire type in {label}: {wire}")


def _validate_fields(fields: Any, enums: dict[str, Any], types: dict[str, Any],
                     label: str) -> list[dict[str, Any]]:
    values = _list(fields, label)
    wires: dict[str, str] = {}
    for index, raw_field in enumerate(values):
        field_label = f"{label}[{index}]"
        require(type(raw_field) is dict, "TYPE",
                f"{field_label} must be a mapping")
        wire = raw_field.get("wire")
        field = _mapping(raw_field, _field_keys(wire, field_label), field_label)
        name = _string(field["name"], f"{field_label}.name")
        require(name not in wires, "DUPLICATE_ID",
                f"duplicate field name in {label}: {name}")
        if wire == "enum_u8":
            require(field["enum"] in enums, "ENUM",
                    f"{field_label} references unknown enum")
        elif wire == "bytes_u8":
            minimum = _integer(field["min_bytes"],
                               f"{field_label}.min_bytes", 0, 255)
            maximum = _integer(field["max_bytes"],
                               f"{field_label}.max_bytes", 0, 255)
            require(minimum <= maximum, "VALUE",
                    f"{field_label} byte bounds are reversed")
        elif wire == "i8":
            minimum = _integer(field["min"], f"{field_label}.min", -128, 127)
            maximum = _integer(field["max"], f"{field_label}.max", -128, 127)
            require(minimum <= maximum, "VALUE",
                    f"{field_label} i8 bounds are reversed")
        elif wire == "repeated":
            _string(field["item_type"], f"{field_label}.item_type")
            count_field = _string(
                field["count_field"], f"{field_label}.count_field"
            )
            require(field["item_type"] in types, "WIRE_TYPE",
                    f"{field_label} references unknown item type")
            require(wires.get(count_field) == "u8", "WIRE_TYPE",
                    f"{field_label} count field must be a preceding u8")
        wires[name] = wire
    return values


def _field_size(field: dict[str, Any]) -> int:
    wire = field["wire"]
    if wire in {"u8", "bool", "enum_u8", "i8"}:
        return 1
    if wire == "u16":
        return 2
    if wire == "bytes_u8":
        return 1 + field["max_bytes"]
    fail("WIRE_TYPE", "repeated field size needs an explicit count")


def _command_map(protocol: dict[str, Any]) -> dict[int, dict[str, Any]]:
    return {item["id"]: item for item in protocol["commands"]}


def _command_name_map(protocol: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["name"]: item for item in protocol["commands"]}


def _event_map(protocol: dict[str, Any]) -> dict[int, dict[str, Any]]:
    return {item["id"]: item for item in protocol["events"]}


def _event_name_map(protocol: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["name"]: item for item in protocol["events"]}


def _validate_protocol(protocol: dict[str, Any]) -> None:
    root = _mapping(protocol, {
        "schema_version", "profile", "protocol", "types", "status_codes",
        "wire_types", "enums", "commands", "events", "wire_rules",
    }, "protocol")
    require(root["schema_version"] == 1 and _is_int(root["schema_version"]),
            "VALUE", "schema_version must be integer 1")

    profile = _mapping(root["profile"], {
        "name", "schema_format", "version", "release_state",
    }, "profile")
    _require_exact(profile, {
        "name": "device-link/v1",
        "schema_format": "fixed-binary/1",
        "version": "1.0.0",
        "release_state": "freeze_candidate",
    }, "VALUE", "profile identity changed")
    _validate_wire_types(root["wire_types"])

    data = _mapping(root["protocol"], {
        "name", "major", "minor", "byte_order", "gatt", "security",
        "transport", "att_errors", "limits",
    }, "protocol.protocol")
    require(_is_int(data["major"]) and _is_int(data["minor"]) and
            (data["name"], data["major"], data["minor"], data["byte_order"]) ==
            ("device-link", 1, 0, "little"), "VALUE",
            "protocol identity or byte order changed")

    gatt = _mapping(data["gatt"], {
        "service", "characteristics", "advertising",
    }, "protocol.gatt")
    service = _mapping(gatt["service"], {"uuid", "att_octets"},
                       "protocol.gatt.service")
    characteristics = _mapping(gatt["characteristics"],
                               {"command_rx", "server_tx"},
                               "protocol.gatt.characteristics")
    command_rx = _mapping(characteristics["command_rx"], {
        "uuid", "att_octets", "properties", "write_procedure",
        "max_value_bytes", "encrypted",
    }, "protocol.gatt.characteristics.command_rx")
    server_tx = _mapping(characteristics["server_tx"], {
        "uuid", "att_octets", "properties", "max_value_bytes", "encrypted",
        "cccd_uuid", "cccd_write_encrypted", "indication_enable_value_le",
    }, "protocol.gatt.characteristics.server_tx")
    expected_uuids = {
        "service": "8f2a8c10-65f6-4f44-9c04-9c4c2f7b6a31",
        "command_rx": "8f2a8c11-65f6-4f44-9c04-9c4c2f7b6a31",
        "server_tx": "8f2a8c12-65f6-4f44-9c04-9c4c2f7b6a31",
    }
    for name, definition in (
        ("service", service), ("command_rx", command_rx),
        ("server_tx", server_tx),
    ):
        _validate_uuid(definition["uuid"], definition["att_octets"], name)
        require(definition["uuid"] == expected_uuids[name], "UUID",
                f"{name} UUID changed")
    _integer(command_rx["max_value_bytes"], "command_rx.max_value_bytes")
    _integer(server_tx["max_value_bytes"], "server_tx.max_value_bytes")
    _integer(server_tx["cccd_uuid"], "server_tx.cccd_uuid")
    require(command_rx["properties"] == ["write"] and
            command_rx["write_procedure"] == "request" and
            server_tx["properties"] == ["indicate"] and
            command_rx["encrypted"] is True and server_tx["encrypted"] is True and
            server_tx["cccd_write_encrypted"] is True,
            "VALUE", "GATT properties or encryption changed")
    require(command_rx["max_value_bytes"] == 495 and
            server_tx["max_value_bytes"] == 495 and
            server_tx["cccd_uuid"] == 0x2902 and
            server_tx["indication_enable_value_le"] == "0200", "VALUE",
            "GATT value budget or CCCD changed")
    advertising = _mapping(gatt["advertising"], {
        "discovery_key", "service_uuid_ad_type", "local_name_prefix",
        "local_name_is_normative",
    }, "protocol.gatt.advertising")
    _require_exact(advertising, {
        "discovery_key": "service_uuid",
        "service_uuid_ad_type": 0x07,
        "local_name_prefix": "MT",
        "local_name_is_normative": False,
    }, "VALUE", "advertising discovery rules changed")

    security = _mapping(data["security"], {
        "transport", "sc_only", "mitm", "bonding", "pairing_window",
        "pairing_window_duration", "qr", "security2", "application_encryption",
    }, "protocol.security")
    _require_exact(security, {
        "transport": "ble_le_secure_connections",
        "sc_only": True,
        "mitm": False,
        "bonding": False,
        "pairing_window": "physical_confirmation",
        "pairing_window_duration": "implementation_defined",
        "qr": False,
        "security2": False,
        "application_encryption": False,
    }, "VALUE", "security profile changed")

    transport_keys = {
        "minimum_att_mtu", "preferred_att_mtu", "required_att_mtu",
        "att_pdu_bytes", "att_value_header_bytes", "maximum_att_value_bytes",
        "l2cap_sdu_bytes", "l2cap_basic_header_bytes", "l2cap_pdu_bytes",
        "link_layer_payload_bytes", "link_layer_payloads_for_full_l2cap_pdu",
        "link_layer_math_requires_dle", "fragmented_messages",
        "single_connection", "request_header", "response_header",
        "event_header", "request_header_bytes", "response_header_bytes",
        "event_header_bytes", "event_marker", "response_opcode_mask",
        "reserved_request_opcodes", "request_opcode_msb_must_be_zero",
        "request_id_min", "request_id_max", "request_id_scope",
        "server_tx_subscription_required", "one_outstanding_indication",
        "write_blocked_while_server_tx_unconfirmed", "request_pending_until",
        "one_active_operation",
        "active_operation_scope", "active_operation_commands",
        "active_operation_allows_queries", "active_request_id_reuse_status",
        "operation_conflict_status", "low_mtu",
    }
    transport = _mapping(data["transport"], transport_keys,
                         "protocol.transport")
    integer_fields = {
        "minimum_att_mtu", "preferred_att_mtu", "required_att_mtu",
        "att_pdu_bytes", "att_value_header_bytes", "maximum_att_value_bytes",
        "l2cap_sdu_bytes", "l2cap_basic_header_bytes", "l2cap_pdu_bytes",
        "link_layer_payload_bytes", "link_layer_payloads_for_full_l2cap_pdu",
        "request_header_bytes", "response_header_bytes", "event_header_bytes",
        "event_marker", "response_opcode_mask", "request_id_min",
        "request_id_max",
    }
    for field in integer_fields:
        _integer(transport[field], f"protocol.transport.{field}")
    reserved_opcodes = _list(transport["reserved_request_opcodes"],
                             "protocol.transport.reserved_request_opcodes")
    for index, opcode in enumerate(reserved_opcodes):
        _integer(opcode, f"reserved_request_opcodes[{index}]", 0, 127)
    require(
        transport["minimum_att_mtu"] == 23 and
        transport["preferred_att_mtu"] == transport["required_att_mtu"] == 498 and
        transport["att_pdu_bytes"] == transport["l2cap_sdu_bytes"] == 498 and
        transport["maximum_att_value_bytes"] ==
        transport["att_pdu_bytes"] - transport["att_value_header_bytes"] == 495 and
        transport["l2cap_pdu_bytes"] ==
        transport["l2cap_sdu_bytes"] + transport["l2cap_basic_header_bytes"] ==
        transport["link_layer_payload_bytes"] *
        transport["link_layer_payloads_for_full_l2cap_pdu"] == 502,
        "TRANSPORT_MATH", "498/495/502 transport math is inconsistent",
    )
    require(
        transport["att_value_header_bytes"] == 3 and
        transport["l2cap_basic_header_bytes"] == 4 and
        transport["link_layer_payload_bytes"] == 251 and
        transport["link_layer_payloads_for_full_l2cap_pdu"] == 2 and
        transport["link_layer_math_requires_dle"] is True and
        transport["fragmented_messages"] is False and
        transport["single_connection"] is True,
        "VALUE", "transport framing scope changed",
    )
    require(
        transport["request_header"] == ["opcode", "request_id"] and
        transport["response_header"] ==
        ["response_opcode", "request_id", "status"] and
        transport["event_header"] == ["event_marker", "event_id"] and
        (transport["request_header_bytes"], transport["response_header_bytes"],
         transport["event_header_bytes"]) == (2, 3, 2) and
        transport["event_marker"] == 0xf0 and
        transport["response_opcode_mask"] == 0x80 and
        transport["reserved_request_opcodes"] == [0x00, 0x70] and
        transport["request_opcode_msb_must_be_zero"] is True and
        (transport["request_id_min"], transport["request_id_max"]) == (1, 255),
        "VALUE", "wire headers changed",
    )
    require(
        transport["request_id_scope"] == "ble_connection" and
        transport["server_tx_subscription_required"] is True and
        transport["one_outstanding_indication"] is True and
        transport["write_blocked_while_server_tx_unconfirmed"] is True and
        transport["request_pending_until"] ==
        "response_indication_confirmed" and
        transport["one_active_operation"] is True and
        transport["active_operation_scope"] == "device" and
        transport["active_request_id_reuse_status"] == "BUSY" and
        transport["operation_conflict_status"] == "BUSY",
        "VALUE", "transaction concurrency rules changed",
    )
    low_mtu = _mapping(transport["low_mtu"], {
        "get_info_minimum_att_mtu", "full_profile_required_att_mtu",
        "other_commands_status",
    }, "protocol.transport.low_mtu")
    _require_exact(low_mtu, {
        "get_info_minimum_att_mtu": transport["minimum_att_mtu"],
        "full_profile_required_att_mtu": transport["required_att_mtu"],
        "other_commands_status": "MTU_TOO_SMALL",
    }, "VALUE", "low MTU policy is inconsistent")

    att_errors = _mapping(data["att_errors"], {
        "insufficient_encryption", "invalid_attribute_value_length",
        "value_not_allowed", "cccd_improperly_configured",
        "procedure_already_in_progress", "gatt_precedence",
        "application_precedence",
    }, "protocol.att_errors")
    _require_exact(att_errors, {
        "insufficient_encryption": 0x0f,
        "invalid_attribute_value_length": 0x0d,
        "value_not_allowed": 0x13,
        "cccd_improperly_configured": 0xfd,
        "procedure_already_in_progress": 0xfe,
        "gatt_precedence": [
            "encrypted_link", "att_value_length", "header_values",
            "server_tx_subscription", "unconfirmed_server_tx",
        ],
        "application_precedence": [
            "unknown_opcode", "get_info_low_mtu_exception", "required_mtu",
            "payload", "active_operation", "service_admission",
        ],
    }, "VALUE", "ATT errors or precedence changed")

    limits = _mapping(data["limits"], {
        "min_ssid_bytes", "max_ssid_bytes", "min_personal_password_bytes",
        "max_personal_password_bytes", "max_scan_networks",
        "maximum_scan_event_bytes", "maximum_get_info_response_bytes",
    }, "protocol.limits")
    _require_exact(limits, {
        "min_ssid_bytes": 1,
        "max_ssid_bytes": 32,
        "min_personal_password_bytes": 8,
        "max_personal_password_bytes": 63,
        "max_scan_networks": 5,
        "maximum_scan_event_bytes": 180,
        "maximum_get_info_response_bytes": 11,
    }, "VALUE", "protocol limits changed")

    _validate_enum(root["status_codes"], {
        "OK": 0, "ACCEPTED": 1, "BUSY": 2, "INVALID_ARGUMENT": 3,
        "NOT_FOUND": 4, "UNAVAILABLE": 5, "STORAGE": 6,
        "MTU_TOO_SMALL": 7, "UNSUPPORTED": 8, "INTERNAL": 9,
    }, "status_codes")
    enums = _mapping(root["enums"], {
        "wifi_security", "wifi_state", "wifi_failure", "operation",
    }, "enums")
    enum_names = {
        "wifi_security": {"OPEN", "PERSONAL"},
        "wifi_state": {
            "UNAVAILABLE", "IDLE", "SCANNING", "CONNECTING", "CONNECTED",
            "ERROR",
        },
        "wifi_failure": {
            "NONE", "AUTHENTICATION", "AP_NOT_FOUND", "TIMEOUT",
            "LINK_LOST", "RADIO", "STORAGE", "INTERNAL",
        },
        "operation": {"SET_CREDENTIALS", "CONNECT", "DISCONNECT", "FORGET"},
    }
    for name, names in enum_names.items():
        _enum_mapping(enums[name], names, f"enums.{name}")

    types = _mapping(root["types"], {"scan_network"}, "types")
    scan_type = _mapping(types["scan_network"], {"fields"},
                         "types.scan_network")
    scan_fields = _validate_fields(scan_type["fields"], enums, types,
                                   "types.scan_network.fields")
    require([field["name"] for field in scan_fields] ==
            ["ssid", "security", "rssi_dbm"], "VALUE",
            "scan network fields changed")
    scan_field_by_name = {field["name"]: field for field in scan_fields}
    require(
        (scan_field_by_name["ssid"]["min_bytes"],
         scan_field_by_name["ssid"]["max_bytes"]) ==
        (limits["min_ssid_bytes"], limits["max_ssid_bytes"]) and
        (scan_field_by_name["rssi_dbm"]["min"],
         scan_field_by_name["rssi_dbm"]["max"]) == (-127, 0),
        "VALUE", "scan field bounds differ from protocol limits",
    )

    command_identity = [
        (1, "GET_INFO"), (2, "GET_STATUS"), (3, "SCAN"),
        (4, "SET_CREDENTIALS"), (5, "CONNECT"), (6, "DISCONNECT"),
        (7, "FORGET"),
    ]
    commands = _list(root["commands"], "commands", nonempty=True)
    seen_commands: list[tuple[int, str]] = []
    for index, raw_command in enumerate(commands):
        label = f"commands[{index}]"
        command = _mapping(raw_command, {
            "id", "name", "request", "response", "asynchronous",
            "completion_event", "allowed_statuses", "requires_full_mtu",
        }, label)
        command_id = _integer(command["id"], f"{label}.id", 1, 127)
        name = _string(command["name"], f"{label}.name")
        seen_commands.append((command_id, name))
        _validate_fields(command["request"], enums, types, f"{label}.request")
        _validate_fields(command["response"], enums, types, f"{label}.response")
        _boolean(command["asynchronous"], f"{label}.asynchronous")
        _boolean(command["requires_full_mtu"], f"{label}.requires_full_mtu")
        statuses = _list(command["allowed_statuses"],
                         f"{label}.allowed_statuses", nonempty=True)
        require(len(statuses) == len(set(statuses)) and
                all(status in root["status_codes"] for status in statuses),
                "STATUS", f"{name} allowed statuses are invalid")
        success = "ACCEPTED" if command["asynchronous"] else "OK"
        require(success in statuses, "STATUS",
                f"{name} omits its success status")
        require((command["completion_event"] is not None) ==
                command["asynchronous"], "VALUE",
                f"{name} completion event and async flag differ")
    require(seen_commands == command_identity, "VALUE",
            "command IDs or order changed")
    command_by_name = _command_name_map(root)
    require(transport["active_operation_commands"] ==
            [name for _, name in command_identity[2:]] and
            transport["active_operation_allows_queries"] ==
            [name for _, name in command_identity[:2]], "VALUE",
            "active operation command sets differ")
    require(command_by_name["GET_INFO"]["requires_full_mtu"] is False and
            all(command_by_name[name]["requires_full_mtu"] is True
                for _, name in command_identity[1:]), "VALUE",
            "full MTU command flags changed")
    require([field["name"] for field in command_by_name["GET_INFO"]["response"]] ==
            ["protocol_major", "protocol_minor", "firmware_major",
             "firmware_minor", "firmware_patch", "pairing_window_open",
             "required_att_mtu"], "VALUE",
            "GET_INFO fixed response fields changed")
    require([field["name"] for field in
             command_by_name["SET_CREDENTIALS"]["request"]] ==
            ["ssid", "password", "security"], "VALUE",
            "SET_CREDENTIALS fields changed")
    credential_fields = {
        field["name"]: field
        for field in command_by_name["SET_CREDENTIALS"]["request"]
    }
    require(
        (credential_fields["ssid"]["min_bytes"],
         credential_fields["ssid"]["max_bytes"]) ==
        (limits["min_ssid_bytes"], limits["max_ssid_bytes"]) and
        (credential_fields["password"]["min_bytes"],
         credential_fields["password"]["max_bytes"]) ==
        (0, limits["max_personal_password_bytes"]),
        "VALUE", "credential field bounds differ from protocol limits",
    )
    info_size = transport["response_header_bytes"] + sum(
        _field_size(field) for field in command_by_name["GET_INFO"]["response"]
    )
    require(info_size == limits["maximum_get_info_response_bytes"] and
            info_size <= transport["minimum_att_mtu"] -
            transport["att_value_header_bytes"], "TRANSPORT_MATH",
            "GET_INFO does not fit the default ATT MTU")

    event_identity = [
        (1, "WIFI_STATUS"), (2, "SCAN_COMPLETE"),
        (3, "OPERATION_COMPLETE"),
    ]
    events = _list(root["events"], "events", nonempty=True)
    seen_events: list[tuple[int, str]] = []
    for index, raw_event in enumerate(events):
        label = f"events[{index}]"
        event = _mapping(raw_event, {"id", "name", "payload"}, label)
        seen_events.append((
            _integer(event["id"], f"{label}.id", 1, 127),
            _string(event["name"], f"{label}.name"),
        ))
        _validate_fields(event["payload"], enums, types, f"{label}.payload")
    require(seen_events == event_identity, "VALUE",
            "event IDs or order changed")
    event_by_name = _event_name_map(root)
    event_names = set(event_by_name)
    for command in commands:
        completion = command["completion_event"]
        require(completion is None or completion in event_names, "VALUE",
                f"{command['name']} references an unknown completion event")
    require(command_by_name["GET_STATUS"]["response"] ==
            event_by_name["WIFI_STATUS"]["payload"], "VALUE",
            "GET_STATUS and WIFI_STATUS snapshots differ")
    require([field["name"] for field in
             event_by_name["SCAN_COMPLETE"]["payload"]] ==
            ["request_id", "failure", "count", "networks"], "VALUE",
            "SCAN_COMPLETE fields changed")
    require([field["name"] for field in
             event_by_name["OPERATION_COMPLETE"]["payload"]] ==
            ["request_id", "operation", "failure"], "VALUE",
            "OPERATION_COMPLETE fields changed")
    require(enums["operation"] == {
        name: command_by_name[name]["id"] for name in enums["operation"]
    }, "VALUE", "operation enum must reuse command opcodes")

    scan_item_max = sum(_field_size(field) for field in scan_fields)
    require(
        transport["event_header_bytes"] + 3 +
        limits["max_scan_networks"] * scan_item_max ==
        limits["maximum_scan_event_bytes"] <=
        transport["maximum_att_value_bytes"],
        "TRANSPORT_MATH", "maximum scan event size is inconsistent",
    )

    rules = _mapping(root["wire_rules"], {
        "response", "admission", "text", "wifi_status", "scan",
        "operation_completion", "sequencing",
    }, "wire_rules")
    response_rules = _mapping(rules["response"], {
        "synchronous_success_status", "asynchronous_success_status",
        "error_payload", "unknown_opcode_status", "malformed_payload_status",
    }, "wire_rules.response")
    _require_exact(response_rules, {
        "synchronous_success_status": "OK",
        "asynchronous_success_status": "ACCEPTED",
        "error_payload": "empty",
        "unknown_opcode_status": "UNSUPPORTED",
        "malformed_payload_status": "INVALID_ARGUMENT",
    }, "VALUE", "response rules changed")

    admission = _mapping(rules["admission"], {
        "service_unavailable_status", "service_unavailable_bypass",
        "profile_required", "profile_missing_status",
    }, "wire_rules.admission")
    bypass = _list(admission["service_unavailable_bypass"],
                   "wire_rules.admission.service_unavailable_bypass")
    profile_required = _list(admission["profile_required"],
                             "wire_rules.admission.profile_required")
    command_names = set(command_by_name)
    require(all(type(name) is str for name in [*bypass, *profile_required]) and
            len(bypass) == len(set(bypass)) and
            len(profile_required) == len(set(profile_required)) and
            set(bypass) <= command_names and
            set(profile_required) <= command_names and
            admission["service_unavailable_status"] in root["status_codes"] and
            admission["profile_missing_status"] in root["status_codes"],
            "VALUE", "command admission rules are inconsistent")
    for name, command in command_by_name.items():
        if name not in bypass:
            require(admission["service_unavailable_status"] in
                    command["allowed_statuses"], "STATUS",
                    f"{name} omits its unavailable admission status")
    for name in profile_required:
        require(admission["profile_missing_status"] in
                command_by_name[name]["allowed_statuses"], "STATUS",
                f"{name} omits its missing-profile status")

    text_rules = _mapping(rules["text"], {
        "ssid_encoding", "ssid_forbidden_unicode_categories",
        "ssid_normalization", "password_encoding", "password_min_octet",
        "password_max_octet", "open_password", "personal_password_bytes",
        "raw_64_hex_psk_supported",
    }, "wire_rules.text")
    _require_exact(text_rules, {
        "ssid_encoding": "utf8",
        "ssid_forbidden_unicode_categories": ["Cc"],
        "ssid_normalization": "none",
        "password_encoding": "printable_ascii",
        "password_min_octet": 0x20,
        "password_max_octet": 0x7e,
        "open_password": "empty",
        "personal_password_bytes": [
            limits["min_personal_password_bytes"],
            limits["max_personal_password_bytes"],
        ],
        "raw_64_hex_psk_supported": False,
    }, "VALUE", "text rules changed")

    wifi_rules = _mapping(rules["wifi_status"], {
        "connected_means_ipv4", "profile_ssid_empty_means_no_profile",
        "state_matrix", "profile_required_states",
        "profile_required_failures", "emitted_when_snapshot_changes",
        "intermediate_updates",
    }, "wire_rules.wifi_status")
    state_matrix = _mapping(
        wifi_rules["state_matrix"], set(enums["wifi_state"]),
        "wire_rules.wifi_status.state_matrix",
    )
    for state, failures in state_matrix.items():
        values = _list(failures, f"state_matrix.{state}", nonempty=True)
        require(len(values) == len(set(values)) and
                all(name in enums["wifi_failure"] for name in values),
                "STATE", f"{state} failure list is invalid")
    require(wifi_rules["connected_means_ipv4"] is True and
            wifi_rules["profile_ssid_empty_means_no_profile"] is True and
            wifi_rules["emitted_when_snapshot_changes"] is True and
            wifi_rules["intermediate_updates"] == "coalesce_latest" and
            set(wifi_rules["profile_required_states"]) <=
            set(enums["wifi_state"]) and
            set(wifi_rules["profile_required_failures"]) <=
            set(enums["wifi_failure"]), "VALUE",
            "Wi-Fi status rules are inconsistent")

    scan_rules = _mapping(rules["scan"], {
        "success_failure", "failure_values", "failure_has_empty_results",
        "filter_empty_ssid", "filter_invalid_utf8",
        "filter_unsupported_security", "deduplicate_by",
        "duplicate_selection", "sort", "maximum_records",
    }, "wire_rules.scan")
    _integer(scan_rules["maximum_records"],
             "wire_rules.scan.maximum_records", 0, 255)
    require(
        scan_rules["success_failure"] == "NONE" and
        set(scan_rules["failure_values"]) <= set(enums["wifi_failure"]) and
        "NONE" not in scan_rules["failure_values"] and
        scan_rules["failure_has_empty_results"] is True and
        scan_rules["filter_empty_ssid"] is True and
        scan_rules["filter_invalid_utf8"] is True and
        scan_rules["filter_unsupported_security"] is True and
        scan_rules["deduplicate_by"] == "ssid_octets" and
        scan_rules["duplicate_selection"] == "strongest_rssi" and
        scan_rules["sort"] ==
        ["rssi_descending", "ssid_octets_ascending"] and
        scan_rules["maximum_records"] == limits["max_scan_networks"],
        "VALUE", "scan rules are inconsistent",
    )

    operation_rules = _mapping(rules["operation_completion"], {
        "success_failure", "failure_matrix", "success_postconditions",
        "failure_rollback_required", "failure_state_source",
    }, "wire_rules.operation_completion")
    operation_matrix = _mapping(
        operation_rules["failure_matrix"], set(enums["operation"]),
        "wire_rules.operation_completion.failure_matrix",
    )
    for operation, failures in operation_matrix.items():
        values = _list(failures, f"failure_matrix.{operation}", nonempty=True)
        require("NONE" in values and len(values) == len(set(values)) and
                all(name in enums["wifi_failure"] for name in values),
                "STATE", f"{operation} failure matrix is invalid")
    postconditions = _mapping(
        operation_rules["success_postconditions"], set(enums["operation"]),
        "wire_rules.operation_completion.success_postconditions",
    )
    require(_same_typed(postconditions, {
        "SET_CREDENTIALS": "profile_saved_without_connecting",
        "CONNECT": "connected_with_ipv4",
        "DISCONNECT": "disconnect_completed",
        "FORGET": "disconnected_and_profile_absent",
    }) and operation_rules["success_failure"] == "NONE" and
            operation_rules["failure_rollback_required"] is False and
            operation_rules["failure_state_source"] == "WIFI_STATUS",
            "VALUE", "operation completion rules are inconsistent")

    sequencing = _mapping(rules["sequencing"], {
        "accepted_response_confirmation_precedes_terminal_event",
        "final_status_confirmation_precedes_terminal_event_if_changed",
        "accepted_operation_terminal_events_exactly_once", "terminal_events",
        "ble_disconnect_operation_behavior", "ble_disconnect_completion_replay",
        "ble_disconnect_request_correlation", "reconnect_recovery",
        "wifi_management_policy_in_contract",
    }, "wire_rules.sequencing")
    terminal_events = _mapping(
        sequencing["terminal_events"],
        set(transport["active_operation_commands"]),
        "wire_rules.sequencing.terminal_events",
    )
    require(
        all(event in event_names for event in terminal_events.values()) and
        all(command_by_name[name]["completion_event"] == event
            for name, event in terminal_events.items()) and
        sequencing[
            "accepted_response_confirmation_precedes_terminal_event"
        ] is True and
        sequencing[
            "final_status_confirmation_precedes_terminal_event_if_changed"
        ] is True and
        sequencing["accepted_operation_terminal_events_exactly_once"] is True and
        sequencing["ble_disconnect_operation_behavior"] == "continue" and
        sequencing["ble_disconnect_completion_replay"] is False and
        sequencing["ble_disconnect_request_correlation"] == "discard" and
        sequencing["reconnect_recovery"] == "GET_STATUS" and
        sequencing["wifi_management_policy_in_contract"] is False,
        "VALUE", "sequencing rules are inconsistent",
    )


def validate_protocol(protocol: dict[str, Any]) -> None:
    try:
        _validate_protocol(protocol)
    except ContractError:
        raise
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise ContractError(
            "TYPE", f"malformed protocol structure: {exc}"
        ) from exc


def validate_version(protocol: dict[str, Any],
                     path: Path = VERSION_PATH) -> None:
    try:
        version = path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise ContractError("LOAD", f"cannot read VERSION: {exc}") from exc
    require(version == "1.0.0\n", "VERSION", "VERSION must be exactly 1.0.0")
    require(protocol["profile"]["version"] == version.strip(), "VERSION",
            "VERSION and protocol profile version differ")


def validate_att_value_length(protocol: dict[str, Any], length: int) -> None:
    require(_is_int(length) and length >= 0, "TYPE",
            "ATT value length must be a non-negative integer")
    maximum = protocol["protocol"]["transport"]["maximum_att_value_bytes"]
    require(length <= maximum, "ATT_VALUE_TOO_LONG",
            f"ATT value length {length} exceeds {maximum}")


def _read_u8(raw: bytes, offset: int, label: str) -> tuple[int, int]:
    require(offset < len(raw), "LENGTH", f"truncated {label}")
    return raw[offset], offset + 1


def _decode_fields_at(protocol: dict[str, Any], fields: list[dict[str, Any]],
                      raw: bytes, offset: int, label: str
                      ) -> tuple[dict[str, Any], int]:
    values: dict[str, Any] = {}
    for field in fields:
        name = field["name"]
        field_label = f"{label}.{name}"
        wire = field["wire"]
        if wire == "u8":
            value, offset = _read_u8(raw, offset, field_label)
        elif wire == "u16":
            require(offset + 2 <= len(raw), "LENGTH",
                    f"truncated {field_label}")
            value = int.from_bytes(raw[offset:offset + 2], "little")
            offset += 2
        elif wire == "bool":
            encoded, offset = _read_u8(raw, offset, field_label)
            require(encoded in {0, 1}, "BOOLEAN",
                    f"{field_label} must be 0 or 1")
            value = encoded == 1
        elif wire == "enum_u8":
            encoded, offset = _read_u8(raw, offset, field_label)
            require(encoded in protocol["enums"][field["enum"]].values(),
                    "ENUM", f"{field_label} uses an unknown enum value")
            value = encoded
        elif wire == "i8":
            encoded, offset = _read_u8(raw, offset, field_label)
            value = encoded - 256 if encoded >= 128 else encoded
            code = "RSSI" if name == "rssi_dbm" else "VALUE"
            require(field["min"] <= value <= field["max"], code,
                    f"{field_label} is outside its i8 bounds")
        elif wire == "bytes_u8":
            length, offset = _read_u8(raw, offset, f"{field_label}.length")
            require(field["min_bytes"] <= length <= field["max_bytes"],
                    "LENGTH", f"{field_label} length is outside bounds")
            require(offset + length <= len(raw), "LENGTH",
                    f"truncated {field_label}")
            value = raw[offset:offset + length]
            offset += length
        elif wire == "repeated":
            count = values.get(field["count_field"])
            require(_is_int(count), "WIRE_TYPE",
                    f"{field_label} count field was not decoded")
            item_fields = protocol["types"][field["item_type"]]["fields"]
            items = []
            for index in range(count):
                item, offset = _decode_fields_at(
                    protocol, item_fields, raw, offset,
                    f"{field_label}[{index}]",
                )
                items.append(item)
            value = items
        else:
            fail("WIRE_TYPE", f"unknown wire type while decoding {field_label}")
        values[name] = value
    return values, offset


def _decode_fields(protocol: dict[str, Any], fields: list[dict[str, Any]],
                   raw: bytes, label: str) -> dict[str, Any]:
    values, offset = _decode_fields_at(protocol, fields, raw, 0, label)
    require(offset == len(raw), "TRAILING", f"trailing bytes in {label}")
    return values


def _enum_name(protocol: dict[str, Any], enum: str, value: int) -> str:
    for name, number in protocol["enums"][enum].items():
        if number == value:
            return name
    fail("ENUM", f"unknown {enum} value: {value}")


def _validate_ssid(protocol: dict[str, Any], value: bytes, label: str,
                   allow_empty: bool) -> None:
    if not value and allow_empty:
        return
    limits = protocol["protocol"]["limits"]
    require(limits["min_ssid_bytes"] <= len(value) <=
            limits["max_ssid_bytes"], "LENGTH",
            f"{label} length is outside SSID bounds")
    try:
        decoded = value.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ContractError("UTF8", f"{label} is not valid UTF-8") from exc
    forbidden = set(
        protocol["wire_rules"]["text"]["ssid_forbidden_unicode_categories"]
    )
    require(all(unicodedata.category(character) not in forbidden
                for character in decoded), "CONTROL",
            f"{label} contains a forbidden control character")


def _validate_status_snapshot(protocol: dict[str, Any],
                              values: dict[str, Any], label: str) -> None:
    _validate_ssid(protocol, values["profile_ssid"],
                   f"{label}.profile_ssid", allow_empty=True)
    state = _enum_name(protocol, "wifi_state", values["state"])
    failure = _enum_name(protocol, "wifi_failure", values["failure"])
    rules = protocol["wire_rules"]["wifi_status"]
    require(failure in rules["state_matrix"][state], "STATE",
            f"{label} state/failure combination is invalid")
    if state in rules["profile_required_states"]:
        require(bool(values["profile_ssid"]), "STATE",
                f"{label} state requires a stored profile")
    if failure in rules["profile_required_failures"]:
        require(bool(values["profile_ssid"]), "STATE",
                f"{label} failure requires a stored profile")


def _validate_credentials(protocol: dict[str, Any],
                          values: dict[str, Any], label: str) -> None:
    _validate_ssid(protocol, values["ssid"], f"{label}.ssid", allow_empty=False)
    security = _enum_name(protocol, "wifi_security", values["security"])
    password = values["password"]
    text_rules = protocol["wire_rules"]["text"]
    if security == "OPEN":
        require(not password, "PASSWORD",
                f"{label} OPEN credentials require an empty password")
        return
    minimum, maximum = text_rules["personal_password_bytes"]
    require(minimum <= len(password) <= maximum, "PASSWORD",
            f"{label} PERSONAL password length is invalid")
    require(all(text_rules["password_min_octet"] <= octet <=
                text_rules["password_max_octet"] for octet in password),
            "PASSWORD", f"{label} PERSONAL password must be printable ASCII")


def _validate_scan_complete(protocol: dict[str, Any],
                            values: dict[str, Any], label: str) -> None:
    request_id = values["request_id"]
    require(1 <= request_id <= 255, "HEADER",
            f"{label} request ID must be nonzero")
    failure = _enum_name(protocol, "wifi_failure", values["failure"])
    rules = protocol["wire_rules"]["scan"]
    allowed = [rules["success_failure"], *rules["failure_values"]]
    require(failure in allowed, "STATE",
            f"{label} scan failure is not allowed")
    networks = values["networks"]
    require(values["count"] == len(networks) and
            len(networks) <= rules["maximum_records"], "LENGTH",
            f"{label} scan record count is invalid")
    if failure != rules["success_failure"]:
        require(not networks, "STATE",
                f"{label} failed scan must have no records")
    ssids: set[bytes] = set()
    for index, network in enumerate(networks):
        ssid = network["ssid"]
        _validate_ssid(protocol, ssid, f"{label}.networks[{index}].ssid",
                       allow_empty=False)
        require(ssid not in ssids, "SCAN_ORDER",
                f"{label} contains a duplicate SSID")
        ssids.add(ssid)
    expected = sorted(
        networks, key=lambda item: (-item["rssi_dbm"], item["ssid"])
    )
    require(networks == expected, "SCAN_ORDER",
            f"{label} scan records are not in canonical order")


def _validate_operation_complete(protocol: dict[str, Any],
                                 values: dict[str, Any], label: str) -> None:
    require(1 <= values["request_id"] <= 255, "HEADER",
            f"{label} request ID must be nonzero")
    operation = _enum_name(protocol, "operation", values["operation"])
    failure = _enum_name(protocol, "wifi_failure", values["failure"])
    matrix = protocol["wire_rules"]["operation_completion"]["failure_matrix"]
    require(failure in matrix[operation], "STATE",
            f"{label} operation/failure combination is invalid")


def _validate_payload_semantics(protocol: dict[str, Any], context: str,
                                values: dict[str, Any], label: str) -> None:
    if context == "GET_INFO.response":
        data = protocol["protocol"]
        require(values["protocol_major"] == data["major"] and
                values["protocol_minor"] == data["minor"], "VERSION",
                f"{label} protocol version differs")
        require(values["required_att_mtu"] ==
                data["transport"]["required_att_mtu"], "TRANSPORT_MATH",
                f"{label} required ATT MTU differs")
    elif context in {"GET_STATUS.response", "WIFI_STATUS.event"}:
        _validate_status_snapshot(protocol, values, label)
    elif context == "SET_CREDENTIALS.request":
        _validate_credentials(protocol, values, label)
    elif context == "SCAN_COMPLETE.event":
        _validate_scan_complete(protocol, values, label)
    elif context == "OPERATION_COMPLETE.event":
        _validate_operation_complete(protocol, values, label)


def _message_shape(case: Any, invalid: bool = False) -> dict[str, Any]:
    require(type(case) is dict, "TYPE", "message case must be a mapping")
    kind = case.get("kind")
    require(type(kind) is str, "TYPE", "message kind must be a string")
    common = {"id", "kind", "status", "hex"}
    if kind in {"request", "response"}:
        keys = common | {"opcode", "request_id"}
    elif kind == "event":
        keys = common | {"event_id"}
    else:
        fail("VALUE", f"invalid message kind: {kind}")
    if invalid:
        keys.add("expected_error")
    return _mapping(case, keys, f"message {case.get('id', '<unknown>')}")


def validate_message(protocol: dict[str, Any],
                     case: dict[str, Any]) -> dict[str, Any]:
    value = _message_shape(case)
    label = _string(value["id"], "message.id")
    raw = _hex(value["hex"], f"{label}.hex")
    validate_att_value_length(protocol, len(raw))
    kind = value["kind"]
    transport = protocol["protocol"]["transport"]
    commands = _command_map(protocol)

    if kind in {"request", "response"}:
        opcode = _integer(value["opcode"], f"{label}.opcode", 0, 127)
        request_id = _integer(value["request_id"],
                              f"{label}.request_id", 1, 255)
        if kind == "request":
            require(value["status"] is None, "STATUS",
                    f"{label} request status must be null")
            require(opcode in commands, "UNSUPPORTED",
                    f"{label} request opcode is not a v1 command")
            require(raw[:2] == bytes((opcode, request_id)), "HEADER",
                    f"{label} request header differs")
            command = commands[opcode]
            payload = _decode_fields(
                protocol, command["request"], raw[2:], f"{label}.payload"
            )
            _validate_payload_semantics(
                protocol, f"{command['name']}.request", payload, label
            )
            return payload

        status = _string(value["status"], f"{label}.status")
        require(status in protocol["status_codes"], "STATUS",
                f"{label} response status is unknown")
        expected_header = bytes((
            opcode | transport["response_opcode_mask"],
            request_id,
            protocol["status_codes"][status],
        ))
        require(raw[:3] == expected_header, "HEADER",
                f"{label} response header differs")
        command = commands.get(opcode)
        if command is None:
            require(status == protocol["wire_rules"]["response"][
                "unknown_opcode_status"], "STATUS",
                f"{label} unknown opcode has the wrong status")
            require(len(raw) == 3, "PAYLOAD",
                    f"{label} unknown opcode response must be empty")
            return {}
        require(status in command["allowed_statuses"], "STATUS",
                f"{label} status is not allowed for {command['name']}")
        success = protocol["wire_rules"]["response"][
            "asynchronous_success_status" if command["asynchronous"]
            else "synchronous_success_status"
        ]
        if status != success:
            require(len(raw) == 3, "PAYLOAD",
                    f"{label} error response must be empty")
            return {}
        payload = _decode_fields(
            protocol, command["response"], raw[3:], f"{label}.payload"
        )
        _validate_payload_semantics(
            protocol, f"{command['name']}.response", payload, label
        )
        return payload

    require(value["status"] is None, "STATUS",
            f"{label} event status must be null")
    event_id = _integer(value["event_id"], f"{label}.event_id", 1, 127)
    event = _event_map(protocol).get(event_id)
    require(event is not None, "ENUM", f"{label} event ID is unknown")
    require(raw[:2] == bytes((transport["event_marker"], event_id)), "HEADER",
            f"{label} event header differs")
    payload = _decode_fields(
        protocol, event["payload"], raw[2:], f"{label}.payload"
    )
    _validate_payload_semantics(
        protocol, f"{event['name']}.event", payload, label
    )
    return payload


def _att_result_name(protocol: dict[str, Any], key: str) -> str:
    require(key in protocol["protocol"]["att_errors"], "VALUE",
            f"unknown ATT error key: {key}")
    return f"att:{key.upper()}"


def _transaction_response(protocol: dict[str, Any], state: dict[str, Any],
                          raw: bytes) -> str:
    data = protocol["protocol"]
    transport = data["transport"]
    rules = protocol["wire_rules"]
    if not state["connected"]:
        fail("SEQUENCE", "write attempted without a BLE connection")
    if not state["encrypted"]:
        return _att_result_name(protocol, "insufficient_encryption")
    maximum = min(
        transport["maximum_att_value_bytes"],
        state["mtu"] - transport["att_value_header_bytes"],
    )
    if len(raw) < transport["request_header_bytes"] or len(raw) > maximum:
        return _att_result_name(protocol, "invalid_attribute_value_length")
    opcode, request_id = raw[0], raw[1]
    if (request_id == 0 or opcode in transport["reserved_request_opcodes"] or
            opcode & transport["response_opcode_mask"]):
        return _att_result_name(protocol, "value_not_allowed")
    if not state["subscribed"]:
        return _att_result_name(protocol, "cccd_improperly_configured")
    if state["pending"] is not None:
        return _att_result_name(protocol, "procedure_already_in_progress")

    command = _command_map(protocol).get(opcode)
    if command is None:
        status = rules["response"]["unknown_opcode_status"]
    elif (command["requires_full_mtu"] and
          state["mtu"] < transport["required_att_mtu"]):
        status = transport["low_mtu"]["other_commands_status"]
    else:
        try:
            payload = _decode_fields(
                protocol, command["request"], raw[2:],
                f"transaction.{command['name']}.request",
            )
            _validate_payload_semantics(
                protocol, f"{command['name']}.request", payload,
                f"transaction.{command['name']}",
            )
        except ContractError:
            status = rules["response"]["malformed_payload_status"]
        else:
            active = state["active"]
            operation_names = set(transport["active_operation_commands"])
            admission = rules["admission"]
            if active is not None and request_id == active["request_id"]:
                status = transport["active_request_id_reuse_status"]
            elif active is not None and command["name"] in operation_names:
                status = transport["operation_conflict_status"]
            elif (not state["service_available"] and command["name"] not in
                  admission["service_unavailable_bypass"]):
                status = admission["service_unavailable_status"]
            elif (command["name"] in admission["profile_required"] and
                  not state["profile_present"]):
                status = admission["profile_missing_status"]
            else:
                status = rules["response"][
                    "asynchronous_success_status" if command["asynchronous"]
                    else "synchronous_success_status"
                ]

    state["pending"] = {"kind": "response"}
    if status == rules["response"]["asynchronous_success_status"]:
        state["active"] = {
            "opcode": opcode,
            "request_id": request_id,
            "deliverable": True,
            "final_status": None,
            "completing": False,
        }
    return f"response:{status}"


def _transaction_event(protocol: dict[str, Any], raw_hex: str,
                       event_id: int, label: str) -> dict[str, Any]:
    return validate_message(protocol, {
        "id": label,
        "kind": "event",
        "event_id": event_id,
        "status": None,
        "hex": raw_hex,
    })


def _validate_success_postcondition(protocol: dict[str, Any],
                                    operation: str,
                                    snapshot: dict[str, Any],
                                    label: str) -> None:
    condition = protocol["wire_rules"]["operation_completion"][
        "success_postconditions"
    ][operation]
    state = _enum_name(protocol, "wifi_state", snapshot["state"])
    has_profile = bool(snapshot["profile_ssid"])
    if condition == "profile_saved_without_connecting":
        require(has_profile, "STATE",
                f"{label} successful credential save needs a profile")
    elif condition == "connected_with_ipv4":
        require(state == "CONNECTED" and has_profile, "STATE",
                f"{label} successful connect needs CONNECTED and a profile")
    elif condition == "disconnect_completed":
        require(state not in {"CONNECTING", "CONNECTED"}, "STATE",
                f"{label} successful disconnect is still connected")
    elif condition == "disconnected_and_profile_absent":
        require(state not in {"CONNECTING", "CONNECTED"} and not has_profile,
                "STATE", f"{label} successful forget postcondition failed")
    else:
        fail("VALUE", f"unknown success postcondition: {condition}")


def _run_transaction(protocol: dict[str, Any],
                     case: dict[str, Any]) -> None:
    label = case["id"]
    initial = _mapping(case["initial"], {
        "connected", "encrypted", "mtu", "subscribed", "profile_present",
        "service_available",
    }, f"{label}.initial")
    state = {
        "connected": _boolean(initial["connected"], f"{label}.connected"),
        "encrypted": _boolean(initial["encrypted"], f"{label}.encrypted"),
        "mtu": _integer(initial["mtu"], f"{label}.mtu", 23, 498),
        "subscribed": _boolean(initial["subscribed"], f"{label}.subscribed"),
        "profile_present": _boolean(initial["profile_present"],
                                    f"{label}.profile_present"),
        "service_available": _boolean(initial["service_available"],
                                      f"{label}.service_available"),
        "pending": None,
        "active": None,
    }
    steps = _list(case["steps"], f"{label}.steps", nonempty=True)
    for index, raw_step in enumerate(steps):
        step_label = f"{label}.steps[{index}]"
        require(type(raw_step) is dict, "TYPE",
                f"{step_label} must be a mapping")
        action = raw_step.get("action")
        require(type(action) is str, "TYPE",
                f"{step_label}.action must be a string")
        if action == "write":
            step = _mapping(raw_step, {"action", "hex", "expect"}, step_label)
            raw = _hex(step["hex"], f"{step_label}.hex")
            expected = _string(step["expect"], f"{step_label}.expect")
            actual = _transaction_response(protocol, state, raw)
            require(actual == expected, "EXPECTATION",
                    f"{step_label} expected {expected}, got {actual}")
        elif action == "confirm_response":
            _mapping(raw_step, {"action"}, step_label)
            require(state["pending"] is not None and
                    state["pending"]["kind"] == "response", "SEQUENCE",
                    f"{step_label} has no response to confirm")
            state["pending"] = None
        elif action == "status":
            step = _mapping(raw_step, {"action", "hex", "final_for"},
                            step_label)
            require(state["connected"] and state["pending"] is None, "SEQUENCE",
                    f"{step_label} cannot queue a status indication")
            values = _transaction_event(
                protocol, step["hex"], 1, f"{step_label}.status"
            )
            final_for = step["final_for"]
            require(final_for is None or
                    (_is_int(final_for) and 1 <= final_for <= 255), "TYPE",
                    f"{step_label}.final_for is invalid")
            if final_for is not None:
                active = state["active"]
                require(active is not None and active["deliverable"] and
                        active["request_id"] == final_for, "SEQUENCE",
                        f"{step_label} final status has no matching operation")
            state["profile_present"] = bool(values["profile_ssid"])
            state["pending"] = {
                "kind": "status", "final_for": final_for, "values": values,
            }
        elif action == "confirm_status":
            _mapping(raw_step, {"action"}, step_label)
            require(state["pending"] is not None and
                    state["pending"]["kind"] == "status", "SEQUENCE",
                    f"{step_label} has no status to confirm")
            final_for = state["pending"]["final_for"]
            if final_for is not None:
                state["active"]["final_status"] = state["pending"]["values"]
            state["pending"] = None
        elif action in {"complete_operation", "complete_scan"}:
            step = _mapping(raw_step, {"action", "hex"}, step_label)
            require(state["connected"] and state["pending"] is None, "SEQUENCE",
                    f"{step_label} cannot queue a completion indication")
            active = state["active"]
            require(active is not None and active["deliverable"] and
                    not active["completing"], "SEQUENCE",
                    f"{step_label} has no deliverable active operation")
            active_command = _command_map(protocol)[active["opcode"]]
            event_name = active_command["completion_event"]
            expected_action = (
                "complete_scan" if event_name == "SCAN_COMPLETE"
                else "complete_operation"
            )
            require(action == expected_action, "SEQUENCE",
                    f"{step_label} uses the wrong terminal event")
            event_id = _event_name_map(protocol)[event_name]["id"]
            if event_name == "OPERATION_COMPLETE":
                values = _transaction_event(
                    protocol, step["hex"], event_id,
                    f"{step_label}.completion",
                )
                require(values["request_id"] == active["request_id"] and
                        values["operation"] == active["opcode"], "SEQUENCE",
                        f"{step_label} completion correlation differs")
                failure = _enum_name(
                    protocol, "wifi_failure", values["failure"]
                )
                operation = _enum_name(
                    protocol, "operation", values["operation"]
                )
                if (failure == protocol["wire_rules"][
                        "operation_completion"]["success_failure"] and
                        active["final_status"] is not None):
                    _validate_success_postcondition(
                        protocol, operation, active["final_status"], step_label
                    )
            else:
                values = _transaction_event(
                    protocol, step["hex"], event_id,
                    f"{step_label}.completion",
                )
                require(values["request_id"] == active["request_id"],
                        "SEQUENCE",
                        f"{step_label} completion request ID differs")
            active["completing"] = True
            state["pending"] = {"kind": "completion"}
        elif action == "confirm_completion":
            _mapping(raw_step, {"action"}, step_label)
            require(state["pending"] is not None and
                    state["pending"]["kind"] == "completion", "SEQUENCE",
                    f"{step_label} has no completion to confirm")
            state["pending"] = None
            state["active"] = None
        elif action == "disconnect":
            _mapping(raw_step, {"action"}, step_label)
            require(state["connected"], "SEQUENCE",
                    f"{step_label} connection is already closed")
            state["connected"] = False
            state["pending"] = None
            if state["active"] is not None:
                state["active"]["deliverable"] = False
                state["active"]["request_id"] = None
        elif action == "reconnect":
            step = _mapping(raw_step, {
                "action", "encrypted", "mtu", "subscribed",
            }, step_label)
            require(not state["connected"], "SEQUENCE",
                    f"{step_label} connection is already open")
            state["connected"] = True
            state["encrypted"] = _boolean(step["encrypted"],
                                          f"{step_label}.encrypted")
            state["mtu"] = _integer(step["mtu"], f"{step_label}.mtu", 23, 498)
            state["subscribed"] = _boolean(step["subscribed"],
                                           f"{step_label}.subscribed")
            state["pending"] = None
        elif action == "finish_detached_operation":
            _mapping(raw_step, {"action"}, step_label)
            require(state["active"] is not None and
                    not state["active"]["deliverable"] and
                    state["pending"] is None, "SEQUENCE",
                    f"{step_label} has no detached operation")
            state["active"] = None
        else:
            fail("VALUE", f"unknown transaction action in {step_label}: {action}")
    require(state["pending"] is None, "SEQUENCE",
            f"{label} ends with an unconfirmed indication")
    require(state["active"] is None, "SEQUENCE",
            f"{label} ends before its active operation terminates")


def _validate_transaction_case(protocol: dict[str, Any],
                               raw_case: Any) -> None:
    require(type(raw_case) is dict, "TYPE",
            "transaction case must be a mapping")
    case = _mapping(raw_case, {
        "id", "initial", "steps", "expected_error",
    }, f"transaction {raw_case.get('id', '<unknown>')}")
    _string(case["id"], "transaction.id")
    expected_error = case["expected_error"]
    require(expected_error is None or
            (type(expected_error) is str and expected_error),
            "TYPE", f"{case['id']}.expected_error is invalid")
    try:
        _run_transaction(protocol, case)
    except ContractError as exc:
        if expected_error is None:
            raise
        require(exc.code == expected_error, "EXPECTATION",
                f"{case['id']} expected {expected_error}, got {exc.code}")
    else:
        require(expected_error is None, "EXPECTATION",
                f"{case['id']} expected {expected_error} but passed")


def _validate_transport_case(protocol: dict[str, Any],
                             raw_case: Any) -> None:
    require(type(raw_case) is dict, "TYPE",
            "transport case must be a mapping")
    case = _mapping(raw_case, {
        "id", "length", "accepted", "hex", "expected_error",
    }, f"transport {raw_case.get('id', '<unknown>')}")
    label = _string(case["id"], "transport.id")
    length = _integer(case["length"], f"{label}.length", 0)
    accepted = _boolean(case["accepted"], f"{label}.accepted")
    raw = _hex(case["hex"], f"{label}.hex")
    require(len(raw) == length, "LENGTH",
            f"{label} declared length differs from hex")
    expected = case["expected_error"]
    require(expected is None or (type(expected) is str and expected), "TYPE",
            f"{label}.expected_error is invalid")
    try:
        validate_att_value_length(protocol, length)
    except ContractError as exc:
        require(not accepted and expected == exc.code, "EXPECTATION",
                f"{label} expected {expected}, got {exc.code}")
    else:
        require(accepted and expected is None, "EXPECTATION",
                f"{label} unexpectedly fits the ATT value budget")


def validate_vectors(protocol: dict[str, Any],
                     vectors: dict[str, Any] | None = None) -> None:
    if vectors is None:
        vectors = load_vectors()
    root = _mapping(vectors, {
        "format_version", "protocol", "messages", "transport_cases",
        "transaction_cases",
    }, "vectors")
    require(root["format_version"] == 2 and
            _is_int(root["format_version"]) and
            root["protocol"] == "device-link/v1", "VERSION",
            "vector identity changed")
    messages = _mapping(root["messages"], {"valid", "invalid"},
                        "vectors.messages")
    valid_cases = _list(messages["valid"], "vectors.messages.valid",
                        nonempty=True)
    invalid_cases = _list(messages["invalid"], "vectors.messages.invalid",
                          nonempty=True)
    transport_cases = _list(root["transport_cases"],
                            "vectors.transport_cases", nonempty=True)
    transaction_cases = _list(root["transaction_cases"],
                              "vectors.transaction_cases", nonempty=True)

    ids: set[str] = set()
    status_coverage: dict[str, set[str]] = {
        command["name"]: set() for command in protocol["commands"]
    }
    request_coverage: set[int] = set()
    event_coverage: set[int] = set()
    state_coverage: set[tuple[str, str]] = set()
    scan_failure_coverage: set[str] = set()
    operation_coverage: set[tuple[str, str]] = set()
    unknown_response = False

    for raw_case in valid_cases:
        case = _message_shape(raw_case)
        case_id = _string(case["id"], "message.id")
        require(case_id not in ids, "DUPLICATE_ID",
                f"duplicate vector ID: {case_id}")
        ids.add(case_id)
        values = validate_message(protocol, case)
        if case["kind"] == "request":
            request_coverage.add(case["opcode"])
        elif case["kind"] == "response":
            command = _command_map(protocol).get(case["opcode"])
            if command is None:
                unknown_response = case["status"] == "UNSUPPORTED"
            else:
                status_coverage[command["name"]].add(case["status"])
        else:
            event_coverage.add(case["event_id"])
            event_name = _event_map(protocol)[case["event_id"]]["name"]
            if event_name == "WIFI_STATUS":
                state_coverage.add((
                    _enum_name(protocol, "wifi_state", values["state"]),
                    _enum_name(protocol, "wifi_failure", values["failure"]),
                ))
            elif event_name == "SCAN_COMPLETE":
                scan_failure_coverage.add(
                    _enum_name(protocol, "wifi_failure", values["failure"])
                )
            else:
                operation_coverage.add((
                    _enum_name(protocol, "operation", values["operation"]),
                    _enum_name(protocol, "wifi_failure", values["failure"]),
                ))

    for raw_case in invalid_cases:
        case = _message_shape(raw_case, invalid=True)
        case_id = _string(case["id"], "message.id")
        require(case_id not in ids, "DUPLICATE_ID",
                f"duplicate vector ID: {case_id}")
        ids.add(case_id)
        expected = _string(case["expected_error"],
                           f"{case_id}.expected_error")
        normal = dict(case)
        del normal["expected_error"]
        try:
            validate_message(protocol, normal)
        except ContractError as exc:
            require(exc.code == expected, "EXPECTATION",
                    f"{case_id} expected {expected}, got {exc.code}")
        else:
            fail("EXPECTATION", f"negative vector passed: {case_id}")

    require(request_coverage == set(_command_map(protocol)), "COVERAGE",
            "valid request vectors do not cover every command")
    for command in protocol["commands"]:
        require(status_coverage[command["name"]] ==
                set(command["allowed_statuses"]), "COVERAGE",
                f"{command['name']} response statuses are not fully covered")
    require(unknown_response, "COVERAGE",
            "unknown opcode UNSUPPORTED response is not covered")
    require(event_coverage == set(_event_map(protocol)), "COVERAGE",
            "valid vectors do not cover every event")

    expected_states = {
        (state, failure)
        for state, failures in protocol["wire_rules"]["wifi_status"][
            "state_matrix"
        ].items()
        for failure in failures
    }
    require(state_coverage == expected_states, "COVERAGE",
            "WIFI_STATUS state/failure matrix is not fully covered")
    scan_rules = protocol["wire_rules"]["scan"]
    require(scan_failure_coverage ==
            {scan_rules["success_failure"], *scan_rules["failure_values"]},
            "COVERAGE", "SCAN_COMPLETE failures are not fully covered")
    expected_operations = {
        (operation, failure)
        for operation, failures in protocol["wire_rules"][
            "operation_completion"
        ]["failure_matrix"].items()
        for failure in failures
    }
    require(operation_coverage == expected_operations, "COVERAGE",
            "OPERATION_COMPLETE failure matrix is not fully covered")

    required_message_ids = {
        "get-info-response", "get-info-mtu23-response",
        "get-status-unavailable",
        "credentials-ssid-min", "credentials-ssid-max",
        "credentials-password-min", "credentials-password-max",
        "credentials-password-octet-bounds",
        "scan-complete-max", "scan-complete-rssi-bounds",
        "scan-distinct-normalization",
    }
    require(required_message_ids <= ids, "COVERAGE",
            "required boundary message vectors are missing")

    transport_ids: set[str] = set()
    transport_lengths: set[tuple[int, bool]] = set()
    for raw_case in transport_cases:
        require(type(raw_case) is dict, "TYPE",
                "transport case must be a mapping")
        case_id = raw_case.get("id")
        require(type(case_id) is str and case_id, "TYPE",
                "transport case ID is invalid")
        require(case_id not in ids and case_id not in transport_ids,
                "DUPLICATE_ID", f"duplicate vector ID: {case_id}")
        transport_ids.add(case_id)
        _validate_transport_case(protocol, raw_case)
        transport_lengths.add((raw_case["length"], raw_case["accepted"]))
    require({(495, True), (496, False)} <= transport_lengths, "COVERAGE",
            "495/496 ATT transport boundaries are missing")

    transaction_ids: set[str] = set()
    for raw_case in transaction_cases:
        require(type(raw_case) is dict, "TYPE",
                "transaction case must be a mapping")
        case_id = raw_case.get("id")
        require(type(case_id) is str and case_id, "TYPE",
                "transaction case ID is invalid")
        require(case_id not in ids and case_id not in transport_ids and
                case_id not in transaction_ids, "DUPLICATE_ID",
                f"duplicate vector ID: {case_id}")
        transaction_ids.add(case_id)
        _validate_transaction_case(protocol, raw_case)
    required_transactions = {
        "get-info-at-mtu23", "full-profile-at-mtu497",
        "full-profile-at-mtu498", "reserved-request-opcodes-at-att",
        "unencrypted-precedence", "unsubscribed-precedence",
        "pending-response-write", "pending-event-write",
        "active-operation-queries",
        "status-before-operation-completion", "scan-terminal-event",
        "connect-success-postcondition", "disconnect-success-postcondition",
        "forget-success-postcondition", "connect-success-invalid-postcondition",
        "disconnect-no-replay", "completion-before-response-confirmation",
        "orphan-completion", "duplicate-completion",
        "service-unavailable", "get-info-bypasses-service-admission",
        "get-status-bypasses-service-admission",
        "connect-without-profile", "forget-without-profile",
        "application-precedence",
    }
    require(required_transactions <= transaction_ids, "COVERAGE",
            "required transaction scenarios are missing")


def normalized_digest(protocol: dict[str, Any],
                      vectors: dict[str, Any] | None = None) -> str:
    if vectors is None:
        vectors = load_vectors()
    encoded = json.dumps(
        {"protocol": protocol, "vectors": vectors},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="validate the Device Link v1 contract"
    )
    parser.add_argument("--print-digest", action="store_true")
    parser.add_argument("--protocol", type=Path, default=PROTOCOL_PATH)
    parser.add_argument("--vectors", type=Path, default=VECTORS_PATH)
    args = parser.parse_args(argv)

    protocol = load_protocol(args.protocol)
    vectors = load_vectors(args.vectors)
    validate_protocol(protocol)
    validate_version(protocol, args.protocol.parent / "VERSION")
    validate_vectors(protocol, vectors)
    digest = normalized_digest(protocol, vectors)
    if args.print_digest:
        print(digest)
    else:
        print("Device Link v1 contract verified")
        print(f"schema_digest={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
