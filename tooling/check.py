from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
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
NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
UINT32_MAX = (1 << 32) - 1
WIRE_RULE_KEYS = {
    "response", "text", "wifi_status", "scan_result", "operation_result",
    "operation_record", "operation_lifecycle", "sequencing",
}


class ContractError(ValueError):
    """Stable validation failure exposed to tests and CI."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code


def fail(code: str, message: str) -> None:
    raise ContractError(code, message)


def require(condition: bool, code: str, message: str) -> None:
    if not condition:
        fail(code, message)


def _is_int(value: Any) -> bool:
    return type(value) is int


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(loader: _UniqueKeyLoader, node: yaml.Node,
                              deep: bool = False) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise ContractError(
                "TYPE", "YAML mapping keys must be hashable"
            ) from exc
        if duplicate:
            fail("DUPLICATE_KEY", f"duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("DUPLICATE_KEY", f"duplicate JSON key: {key}")
        result[key] = value
    return result


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


def _mapping(value: Any, required: set[str], optional: set[str],
             label: str) -> dict[str, Any]:
    require(type(value) is dict, "TYPE", f"{label} must be a mapping")
    require(all(type(key) is str for key in value), "TYPE",
            f"{label} keys must be strings")
    actual = set(value)
    missing = required - actual
    unknown = actual - required - optional
    require(not missing, "MISSING_FIELD",
            f"{label} missing fields: {sorted(missing)}")
    require(not unknown, "UNKNOWN_FIELD",
            f"{label} unknown fields: {sorted(unknown)}")
    return value


def _named_mapping(value: Any, label: str,
                   nonempty: bool = True) -> dict[str, Any]:
    require(type(value) is dict, "TYPE", f"{label} must be a mapping")
    require(all(type(key) is str and key for key in value), "TYPE",
            f"{label} keys must be non-empty strings")
    require(not nonempty or bool(value), "LENGTH",
            f"{label} must not be empty")
    return value


def _list(value: Any, label: str, nonempty: bool = False) -> list[Any]:
    require(type(value) is list, "TYPE", f"{label} must be a list")
    require(not nonempty or bool(value), "LENGTH",
            f"{label} must not be empty")
    return value


def _string(value: Any, label: str) -> str:
    require(type(value) is str and bool(value), "TYPE",
            f"{label} must be a non-empty string")
    return value


def _optional_string(value: Any, label: str) -> str | None:
    require(value is None or (type(value) is str and bool(value)), "TYPE",
            f"{label} must be null or a non-empty string")
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


def _string_list(value: Any, label: str,
                 nonempty: bool = False) -> list[str]:
    values = _list(value, label, nonempty)
    for index, item in enumerate(values):
        _string(item, f"{label}[{index}]")
    return values


def _hex(value: Any, label: str) -> bytes:
    require(type(value) is str and len(value) % 2 == 0 and
            HEX_RE.fullmatch(value) is not None,
            "HEX", f"{label} must be lowercase even-length hex")
    return bytes.fromhex(value)


def _validate_uuid(definition: Any, label: str) -> None:
    item = _mapping(definition, {"uuid", "att_octets"}, set(), label)
    text = _string(item["uuid"], f"{label}.uuid")
    try:
        parsed = uuid.UUID(text)
    except (ValueError, AttributeError) as exc:
        raise ContractError("UUID", f"invalid UUID: {label}") from exc
    require(str(parsed) == text, "UUID",
            f"{label} UUID must use canonical lowercase text")
    raw = _hex(item["att_octets"], f"{label}.att_octets")
    require(len(raw) == 16, "UUID", f"{label} ATT UUID must be 16 bytes")
    require(raw == parsed.bytes[::-1], "UUID",
            f"{label} ATT UUID octet order is incorrect")


def _validate_number_registry(value: Any, label: str) -> dict[str, int]:
    mapping = _named_mapping(value, label)
    numbers: list[int] = []
    for name, number in mapping.items():
        require(NAME_RE.fullmatch(name) is not None, "VALUE",
                f"invalid name in {label}: {name}")
        numbers.append(_integer(number, f"{label}.{name}", 0, 255))
    require(len(numbers) == len(set(numbers)), "DUPLICATE_ID",
            f"{label} numeric values must be unique")
    return mapping


def _validate_wire_types(value: Any) -> dict[str, Any]:
    definitions = _named_mapping(value, "wire_types")
    required = {"u8", "u16", "u32", "i8", "bool", "enum_u8",
                "bytes_u8", "repeated"}
    require(set(definitions) == required, "WIRE_TYPE",
            "wire type set is incomplete or unsupported")
    expected = {
        "u8": {"size_bytes": 1, "encoding": "unsigned"},
        "u16": {"size_bytes": 2, "encoding": "unsigned",
                "byte_order": "little"},
        "u32": {"size_bytes": 4, "encoding": "unsigned",
                "byte_order": "little"},
        "i8": {"size_bytes": 1, "encoding": "twos_complement"},
        "bool": {"size_bytes": 1, "false_value": 0, "true_value": 1},
        "enum_u8": {"base": "u8"},
        "bytes_u8": {"length_prefix": "u8", "length_unit": "octets"},
        "repeated": {"count_source": "named_prior_u8_field",
                     "item_encoding": "concatenated"},
    }
    for name, shape in expected.items():
        actual = _mapping(definitions[name], set(shape), set(),
                          f"wire_types.{name}")
        require(actual == shape, "WIRE_TYPE",
                f"wire_types.{name} encoding is inconsistent")
    return definitions


def _field_keys(wire: Any, label: str) -> tuple[set[str], set[str]]:
    require(type(wire) is str, "TYPE", f"{label}.wire must be a string")
    required = {"name", "wire"}
    if wire in {"u8", "u16", "u32"}:
        return required, {"nonzero"}
    if wire == "bool":
        return required, set()
    if wire == "enum_u8":
        return required | {"enum"}, set()
    if wire == "i8":
        return required | {"min", "max"}, set()
    if wire == "bytes_u8":
        return required | {"min_bytes", "max_bytes"}, {
            "encoding", "text_rule", "limit_ref",
            "forbidden_unicode_categories",
        }
    if wire == "repeated":
        return required | {"item_type", "count_field", "max_count"}, {"limit_ref"}
    fail("WIRE_TYPE", f"unknown wire type in {label}: {wire}")


def _validate_fields(fields: Any, enums: dict[str, Any],
                     types: dict[str, Any], label: str) -> list[dict[str, Any]]:
    result = _list(fields, label)
    prior_wires: dict[str, str] = {}
    for index, raw in enumerate(result):
        field_label = f"{label}[{index}]"
        require(type(raw) is dict, "TYPE",
                f"{field_label} must be a mapping")
        required, optional = _field_keys(raw.get("wire"), field_label)
        field = _mapping(raw, required, optional, field_label)
        name = _string(field["name"], f"{field_label}.name")
        require(name not in prior_wires, "DUPLICATE_ID",
                f"duplicate field name in {label}: {name}")
        wire = field["wire"]
        if wire in {"u8", "u16", "u32"} and "nonzero" in field:
            _boolean(field["nonzero"], f"{field_label}.nonzero")
        elif wire == "enum_u8":
            enum_name = _string(field["enum"], f"{field_label}.enum")
            require(enum_name in enums, "ENUM",
                    f"{field_label} references unknown enum {enum_name}")
        elif wire == "i8":
            minimum = _integer(field["min"], f"{field_label}.min", -128, 127)
            maximum = _integer(field["max"], f"{field_label}.max", -128, 127)
            require(minimum <= maximum, "VALUE",
                    f"{field_label} bounds are reversed")
        elif wire == "bytes_u8":
            minimum = _integer(field["min_bytes"],
                               f"{field_label}.min_bytes", 0, 255)
            maximum = _integer(field["max_bytes"],
                               f"{field_label}.max_bytes", 0, 255)
            require(minimum <= maximum, "VALUE",
                    f"{field_label} byte bounds are reversed")
            if "encoding" in field:
                require(field["encoding"] in {"utf8", "printable_ascii"},
                        "VALUE", f"{field_label} has unknown text encoding")
            if "text_rule" in field:
                _string(field["text_rule"], f"{field_label}.text_rule")
            if "limit_ref" in field:
                _string(field["limit_ref"], f"{field_label}.limit_ref")
            categories = field.get("forbidden_unicode_categories", [])
            _string_list(categories,
                         f"{field_label}.forbidden_unicode_categories")
            require(not categories or field.get("encoding") == "utf8",
                    "VALUE", f"{field_label} categories require UTF-8")
        elif wire == "repeated":
            item_type = _string(field["item_type"],
                                f"{field_label}.item_type")
            count_field = _string(field["count_field"],
                                  f"{field_label}.count_field")
            require(item_type in types, "WIRE_TYPE",
                    f"{field_label} references unknown type {item_type}")
            require(prior_wires.get(count_field) == "u8", "WIRE_TYPE",
                    f"{field_label} count must reference a prior u8")
            _integer(field["max_count"], f"{field_label}.max_count", 0, 255)
            if "limit_ref" in field:
                _string(field["limit_ref"], f"{field_label}.limit_ref")
        prior_wires[name] = wire
    return result


def _fields_max_size(fields: list[dict[str, Any]], types: dict[str, Any],
                     stack: tuple[str, ...] = ()) -> int:
    size = 0
    for field in fields:
        wire = field["wire"]
        if wire in {"u8", "i8", "bool", "enum_u8"}:
            size += 1
        elif wire == "u16":
            size += 2
        elif wire == "u32":
            size += 4
        elif wire == "bytes_u8":
            size += 1 + field["max_bytes"]
        elif wire == "repeated":
            type_name = field["item_type"]
            require(type_name not in stack, "WIRE_TYPE",
                    f"recursive wire type: {' -> '.join(stack + (type_name,))}")
            item_fields = types[type_name]["fields"]
            size += field["max_count"] * _fields_max_size(
                item_fields, types, stack + (type_name,)
            )
        else:
            fail("WIRE_TYPE", f"cannot size wire type {wire}")
    return size


def _command_maps(protocol: dict[str, Any]) -> tuple[dict[int, Any],
                                                     dict[str, Any]]:
    by_id = {item["id"]: item for item in protocol["commands"]}
    by_name = {item["name"]: item for item in protocol["commands"]}
    return by_id, by_name


def _event_maps(protocol: dict[str, Any]) -> tuple[dict[int, Any],
                                                   dict[str, Any]]:
    by_id = {item["id"]: item for item in protocol["events"]}
    by_name = {item["name"]: item for item in protocol["events"]}
    return by_id, by_name


def _validate_gatt(data: Any) -> dict[str, Any]:
    gatt = _mapping(data, {"service", "characteristics", "advertising"},
                    set(), "protocol.gatt")
    _validate_uuid(gatt["service"], "protocol.gatt.service")
    characteristics = _mapping(
        gatt["characteristics"], {"command_rx", "server_tx"}, set(),
        "protocol.gatt.characteristics",
    )
    command = _mapping(characteristics["command_rx"], {
        "uuid", "att_octets", "properties", "write_procedure",
        "max_value_bytes", "encrypted", "authenticated",
    }, set(), "protocol.gatt.characteristics.command_rx")
    server = _mapping(characteristics["server_tx"], {
        "uuid", "att_octets", "properties", "max_value_bytes", "encrypted",
        "authenticated", "cccd_uuid", "cccd_write_encrypted",
        "cccd_write_authenticated", "indication_enable_value_le",
    }, set(), "protocol.gatt.characteristics.server_tx")
    _validate_uuid({key: command[key] for key in ("uuid", "att_octets")},
                   "protocol.gatt.characteristics.command_rx")
    _validate_uuid({key: server[key] for key in ("uuid", "att_octets")},
                   "protocol.gatt.characteristics.server_tx")
    uuid_texts = [gatt["service"]["uuid"], command["uuid"], server["uuid"]]
    uuid_octets = [gatt["service"]["att_octets"], command["att_octets"],
                   server["att_octets"]]
    require(len(uuid_texts) == len(set(uuid_texts)) and
            len(uuid_octets) == len(set(uuid_octets)), "DUPLICATE_ID",
            "GATT service and characteristic UUIDs must be unique")
    require(_string_list(command["properties"], "command_rx.properties") ==
            ["write"], "VALUE", "command_rx must use Write Request")
    require(command["write_procedure"] == "request", "VALUE",
            "command_rx write procedure must be request")
    require(_string_list(server["properties"], "server_tx.properties") ==
            ["indicate"], "VALUE", "server_tx must use indications")
    for label, item in (("command_rx", command), ("server_tx", server)):
        _integer(item["max_value_bytes"], f"{label}.max_value_bytes", 1)
        require(_boolean(item["encrypted"], f"{label}.encrypted"),
                "SECURITY", f"{label} must require encryption")
        require(_boolean(item["authenticated"], f"{label}.authenticated"),
                "SECURITY", f"{label} must require authentication")
    require(_integer(server["cccd_uuid"], "server_tx.cccd_uuid") == 0x2902,
            "VALUE", "server_tx CCCD must be 0x2902")
    require(_boolean(server["cccd_write_encrypted"],
                     "server_tx.cccd_write_encrypted"),
            "SECURITY", "CCCD write must require encryption")
    require(_boolean(server["cccd_write_authenticated"],
                     "server_tx.cccd_write_authenticated"),
            "SECURITY", "CCCD write must require authentication")
    require(_hex(server["indication_enable_value_le"],
                 "server_tx.indication_enable_value_le") == b"\x02\x00",
            "VALUE", "CCCD indication value must be 0200")
    advertising = _mapping(gatt["advertising"], {
        "discovery_key", "service_uuid_ad_type", "local_name_prefix",
        "local_name_is_normative",
    }, set(), "protocol.gatt.advertising")
    require(advertising["discovery_key"] == "service_uuid", "VALUE",
            "advertising discovery must use the service UUID")
    require(_integer(advertising["service_uuid_ad_type"],
                     "advertising.service_uuid_ad_type", 0, 255) == 0x07,
            "VALUE", "complete service UUID AD type must be 0x07")
    _string(advertising["local_name_prefix"], "advertising.local_name_prefix")
    _boolean(advertising["local_name_is_normative"],
             "advertising.local_name_is_normative")
    return gatt


def _validate_security(value: Any) -> dict[str, Any]:
    security = _mapping(value, {
        "transport", "sc_only", "mitm", "bonding", "max_bonds",
        "io_capability", "association_model", "encryption_key_bytes",
        "pairing_window", "pairing_window_duration",
        "unbonded_pairing_requires_window",
        "bonded_reconnect_requires_window", "bond_replacement", "oob",
        "application_encryption",
    }, set(), "protocol.security")
    require(_string(security["transport"], "security.transport") ==
            "ble_le_secure_connections", "SECURITY",
            "transport must use LE Secure Connections")
    require(_boolean(security["sc_only"], "security.sc_only"), "SECURITY",
            "legacy pairing must be disabled")
    require(_boolean(security["mitm"], "security.mitm"), "SECURITY",
            "credential transport requires MITM protection")
    require(_boolean(security["bonding"], "security.bonding"), "SECURITY",
            "disconnect recovery requires a retained bond")
    require(_integer(security["max_bonds"], "security.max_bonds", 1) == 1,
            "SECURITY", "exactly one bond is supported")
    require(security["io_capability"] == "display_yes_no", "SECURITY",
            "Numeric Comparison requires DisplayYesNo")
    require(security["association_model"] == "numeric_comparison", "SECURITY",
            "association model must be Numeric Comparison")
    require(_integer(security["encryption_key_bytes"],
                     "security.encryption_key_bytes", 7, 16) == 16,
            "SECURITY", "the encryption key must be 16 bytes")
    require(security["pairing_window"] == "physical_confirmation" and
            security["bond_replacement"] == "local_clear_then_pair",
            "SECURITY", "replacement requires local clear before pairing")
    _string(security["pairing_window_duration"],
            "security.pairing_window_duration")
    require(_boolean(security["unbonded_pairing_requires_window"],
                     "security.unbonded_pairing_requires_window"),
            "SECURITY", "unbonded pairing must require the window")
    require(not _boolean(security["bonded_reconnect_requires_window"],
                         "security.bonded_reconnect_requires_window"),
            "SECURITY", "bonded reconnect must work outside the window")
    require(not _boolean(security["oob"], "security.oob") and
            not _boolean(security["application_encryption"],
                         "security.application_encryption"),
            "SECURITY", "OOB and application encryption are not defined")
    return security


def _validate_transport(value: Any) -> dict[str, Any]:
    keys = {
        "minimum_att_mtu", "preferred_att_mtu", "required_att_mtu",
        "att_pdu_bytes", "att_value_header_bytes", "maximum_att_value_bytes",
        "future_single_att_value_capacity", "fragmented_messages",
        "single_connection", "request_header", "response_header",
        "event_header", "request_header_bytes", "response_header_bytes",
        "event_header_bytes", "event_marker", "response_opcode_mask",
        "application_error_opcode",
        "reserved_request_opcodes", "request_opcode_msb_must_be_zero",
        "request_id_min", "request_id_max", "request_id_scope",
        "operation_id_wire", "operation_id_zero_reserved",
        "operation_id_reuse_within_boot", "operation_id_wrap",
        "operation_id_exhausted_status",
        "operation_id_scope", "server_tx_subscription_required",
        "one_outstanding_indication",
        "write_blocked_while_server_tx_unconfirmed", "request_pending_until",
        "operation_slot_capacity", "operation_slot_commands",
        "operation_slot_queries", "operation_slot_controls",
        "operation_slot_occupied_status",
        "terminal_record_retained_until",
        "terminal_event_replay_on_reconnect", "low_mtu",
    }
    transport = _mapping(value, keys, set(), "protocol.transport")
    numeric = {
        name: _integer(transport[name], f"transport.{name}", 0)
        for name in (
            "minimum_att_mtu", "preferred_att_mtu", "required_att_mtu",
            "att_pdu_bytes", "att_value_header_bytes",
            "maximum_att_value_bytes",
            "request_header_bytes", "response_header_bytes",
            "event_header_bytes", "event_marker", "response_opcode_mask",
            "application_error_opcode",
            "request_id_min", "request_id_max", "operation_slot_capacity",
        )
    }
    require(numeric["minimum_att_mtu"] == 23, "TRANSPORT_MATH",
            "minimum ATT MTU must be 23")
    require(numeric["preferred_att_mtu"] == numeric["required_att_mtu"] ==
            numeric["att_pdu_bytes"], "TRANSPORT_MATH",
            "preferred, required, and ATT PDU sizes must match")
    require(numeric["maximum_att_value_bytes"] ==
            numeric["att_pdu_bytes"] - numeric["att_value_header_bytes"],
            "TRANSPORT_MATH", "ATT value capacity is inconsistent")
    require(numeric["application_error_opcode"] ==
            numeric["response_opcode_mask"] == 0x80, "OPERATION",
            "application error opcode must be the reserved response for opcode zero")
    require(numeric["application_error_opcode"] != numeric["event_marker"],
            "DUPLICATE_ID", "application error opcode collides with event marker")
    for key in (
        "future_single_att_value_capacity",
        "single_connection", "request_opcode_msb_must_be_zero",
        "operation_id_zero_reserved", "server_tx_subscription_required",
        "one_outstanding_indication",
        "write_blocked_while_server_tx_unconfirmed",
    ):
        require(_boolean(transport[key], f"transport.{key}"), "VALUE",
                f"transport.{key} must be true")
    require(not _boolean(transport["fragmented_messages"],
                         "transport.fragmented_messages"), "VALUE",
            "application fragmentation is not supported")
    require(not _boolean(transport["terminal_event_replay_on_reconnect"],
                         "transport.terminal_event_replay_on_reconnect"),
            "OPERATION", "terminal events must not auto-replay")
    headers = (
        ("request_header", "request_header_bytes"),
        ("response_header", "response_header_bytes"),
        ("event_header", "event_header_bytes"),
    )
    for header, count in headers:
        values = _string_list(transport[header], f"transport.{header}", True)
        require(len(values) == numeric[count], "TRANSPORT_MATH",
                f"transport.{header} byte count is inconsistent")
    reserved = _list(transport["reserved_request_opcodes"],
                     "transport.reserved_request_opcodes", True)
    reserved_values = [
        _integer(item, f"reserved_request_opcodes[{index}]", 0, 127)
        for index, item in enumerate(reserved)
    ]
    require(len(reserved_values) == len(set(reserved_values)), "DUPLICATE_ID",
            "reserved request opcodes must be unique")
    collision_sources = {
        numeric["event_marker"] ^ numeric["response_opcode_mask"],
        numeric["application_error_opcode"] ^ numeric["response_opcode_mask"],
    }
    require(collision_sources <= set(reserved_values), "DUPLICATE_ID",
            "request opcodes that collide after response masking must be reserved")
    require(numeric["request_id_min"] > 0 and
            numeric["request_id_min"] <= numeric["request_id_max"] <= 255,
            "VALUE", "request ID range is invalid")
    require(transport["request_id_scope"] == "ble_connection",
            "OPERATION", "request IDs must be connection scoped")
    require(transport["operation_id_wire"] == "u32" and
            transport["operation_id_scope"] == "boot",
            "OPERATION", "operation IDs must be boot-scoped u32")
    require(not _boolean(transport["operation_id_reuse_within_boot"],
                         "transport.operation_id_reuse_within_boot") and
            transport["operation_id_wrap"] == "reject_until_reboot",
            "OPERATION", "operation IDs must not wrap or repeat within one boot")
    require(transport["request_pending_until"] ==
            "response_indication_confirmed", "OPERATION",
            "requests must remain pending through response confirmation")
    require(numeric["operation_slot_capacity"] == 1, "OPERATION",
            "operation slot capacity must be one")
    _string_list(transport["operation_slot_commands"],
                 "transport.operation_slot_commands", True)
    _string_list(transport["operation_slot_queries"],
                 "transport.operation_slot_queries", True)
    _string_list(transport["operation_slot_controls"],
                 "transport.operation_slot_controls", True)
    _string(transport["operation_slot_occupied_status"],
            "transport.operation_slot_occupied_status")
    _string(transport["operation_id_exhausted_status"],
            "transport.operation_id_exhausted_status")
    require(transport["terminal_record_retained_until"] == "ack_or_reboot",
            "OPERATION", "terminal records must survive until ACK or reboot")
    low_mtu = _mapping(transport["low_mtu"], {
        "get_info_minimum_att_mtu", "full_profile_required_att_mtu",
        "recovery_requires_full_mtu", "other_commands_status",
    }, set(), "transport.low_mtu")
    require(_integer(low_mtu["get_info_minimum_att_mtu"],
                     "low_mtu.get_info_minimum_att_mtu") ==
            numeric["minimum_att_mtu"], "TRANSPORT_MATH",
            "low-MTU information threshold is inconsistent")
    require(_integer(low_mtu["full_profile_required_att_mtu"],
                     "low_mtu.full_profile_required_att_mtu") ==
            numeric["required_att_mtu"], "TRANSPORT_MATH",
            "full profile MTU threshold is inconsistent")
    _string(low_mtu["other_commands_status"],
            "low_mtu.other_commands_status")
    require(_boolean(low_mtu["recovery_requires_full_mtu"],
                     "low_mtu.recovery_requires_full_mtu"), "OPERATION",
            "operation recovery must require the full profile MTU")
    return transport


def _validate_att_errors(value: Any) -> dict[str, Any]:
    errors = _mapping(value, {
        "insufficient_authentication", "insufficient_encryption",
        "security_gate_error",
        "invalid_attribute_value_length", "value_not_allowed",
        "profile_cccd_not_enabled", "profile_tx_indication_pending",
        "gatt_precedence", "application_precedence",
    }, set(), "protocol.att_errors")
    fixed = {
        "insufficient_authentication": 0x05,
        "insufficient_encryption": 0x0f,
        "invalid_attribute_value_length": 0x0d,
        "value_not_allowed": 0x13,
        "profile_cccd_not_enabled": 0xfd,
        "profile_tx_indication_pending": 0xfe,
    }
    for name, expected in fixed.items():
        require(_integer(errors[name], f"att_errors.{name}", 0, 255) ==
                expected, "VALUE", f"ATT error {name} must be {expected:#04x}")
    error_values = [errors[name] for name in fixed]
    require(len(error_values) == len(set(error_values)), "DUPLICATE_ID",
            "ATT error values must be unique")
    require(errors["security_gate_error"] == "insufficient_authentication",
            "SECURITY", "NimBLE SC-only security gate must use 0x05")
    gatt_precedence = _string_list(errors["gatt_precedence"],
                                   "att_errors.gatt_precedence", True)
    require(gatt_precedence == [
        "security_gate", "att_value_length",
        "header_values", "server_tx_subscription", "unconfirmed_server_tx",
    ], "SECURITY", "GATT precedence is incomplete or reordered")
    application_precedence = _string_list(
        errors["application_precedence"],
        "att_errors.application_precedence", True,
    )
    require(application_precedence == [
        "unknown_opcode", "get_info_low_mtu_exception", "required_mtu",
        "payload", "operation_slot", "observable_precondition",
    ], "OPERATION", "application precedence is incomplete or reordered")
    return errors


def _validate_limits(value: Any) -> dict[str, Any]:
    numeric_keys = {
        "min_ssid_bytes", "max_ssid_bytes", "min_personal_password_bytes",
        "max_personal_password_bytes", "min_scan_networks",
        "max_scan_networks",
        "maximum_scan_event_bytes", "maximum_get_operation_response_bytes",
        "maximum_get_info_response_bytes",
    }
    limits = _mapping(value, numeric_keys | {"bindings"}, set(),
                      "protocol.limits")
    result = {
        key: _integer(limits[key], f"limits.{key}", 0)
        for key in numeric_keys
    }
    bindings = _named_mapping(limits["bindings"], "limits.bindings")
    validated_bindings: dict[str, Any] = {}
    for name, raw in bindings.items():
        binding = _mapping(raw, {
            "minimum", "maximum", "zero_length_allowed",
        }, set(), f"limits.bindings.{name}")
        minimum = _string(binding["minimum"],
                          f"limits.bindings.{name}.minimum")
        maximum = _string(binding["maximum"],
                          f"limits.bindings.{name}.maximum")
        require(minimum in result and maximum in result, "MISSING_FIELD",
                f"limits binding {name} references an unknown limit")
        require(result[minimum] <= result[maximum], "VALUE",
                f"limits binding {name} is reversed")
        _boolean(binding["zero_length_allowed"],
                 f"limits.bindings.{name}.zero_length_allowed")
        validated_bindings[name] = binding
    result["bindings"] = validated_bindings
    return result


def _iter_protocol_fields(protocol: dict[str, Any]):
    for definition in protocol["types"].values():
        yield from definition["fields"]
    for command in protocol["commands"]:
        yield from command["request"]
        yield from command["response"]
    for event in protocol["events"]:
        yield from event["payload"]


def _validate_field_rule_links(protocol: dict[str, Any],
                               limits: dict[str, Any]) -> None:
    bindings = limits["bindings"]
    text_rules = protocol["wire_rules"]["text"]["text_rules"]
    used_bindings: set[str] = set()
    used_text_rules: set[str] = set()
    for field in _iter_protocol_fields(protocol):
        wire = field["wire"]
        if wire == "bytes_u8":
            rule_name = _string(field.get("text_rule"),
                                f"field {field['name']}.text_rule")
            require(rule_name in text_rules, "MISSING_FIELD",
                    f"field {field['name']} references an unknown text rule")
            rule = text_rules[rule_name]
            require(field.get("encoding") == rule["encoding"], "VALUE",
                    f"field {field['name']} text encoding differs from its rule")
            if rule["encoding"] == "utf8":
                require(field.get("forbidden_unicode_categories", []) ==
                        rule["forbidden_unicode_categories"], "VALUE",
                        f"field {field['name']} Unicode rules differ")
            used_text_rules.add(rule_name)
        if wire not in {"bytes_u8", "repeated"}:
            continue
        binding_name = _string(field.get("limit_ref"),
                               f"field {field['name']}.limit_ref")
        require(binding_name in bindings, "MISSING_FIELD",
                f"field {field['name']} references an unknown limit binding")
        binding = bindings[binding_name]
        minimum = limits[binding["minimum"]]
        maximum = limits[binding["maximum"]]
        field_minimum = field["min_bytes"] if wire == "bytes_u8" else 0
        field_maximum = (field["max_bytes"] if wire == "bytes_u8" else
                         field["max_count"])
        allowed_minimums = {minimum}
        if binding["zero_length_allowed"]:
            allowed_minimums.add(0)
        require(field_minimum in allowed_minimums and field_maximum == maximum,
                "VALUE", f"field {field['name']} differs from its limit binding")
        used_bindings.add(binding_name)
    require(used_bindings == set(bindings), "COVERAGE",
            "limit bindings must all be referenced by wire fields")
    require(used_text_rules == set(text_rules), "COVERAGE",
            "text rules must all be referenced by wire fields")


def _validate_commands(protocol: dict[str, Any], types: dict[str, Any],
                       enums: dict[str, Any], statuses: dict[str, int],
                       transport: dict[str, Any],
                       success_rules: dict[str, Any]) -> None:
    commands = _list(protocol["commands"], "commands", True)
    ids: set[int] = set()
    names: set[str] = set()
    semantics = {"link_info", "wifi_status", "credentials",
                 "operation_record"}
    reserved = set(transport["reserved_request_opcodes"])
    maximum = transport["maximum_att_value_bytes"]
    low_mtu_commands: set[str] = set()
    event_names = {item.get("name") for item in protocol["events"]
                   if type(item) is dict}
    for index, raw in enumerate(commands):
        label = f"commands[{index}]"
        command = _mapping(raw, {
            "id", "name", "request", "response", "asynchronous",
            "completion_event", "allowed_statuses", "requires_full_mtu",
        }, {"request_semantic", "response_semantic"}, label)
        command_id = _integer(command["id"], f"{label}.id", 1, 127)
        name = _string(command["name"], f"{label}.name")
        require(NAME_RE.fullmatch(name) is not None, "VALUE",
                f"invalid command name: {name}")
        require(command_id not in ids and command_id not in reserved,
                "DUPLICATE_ID", f"duplicate or reserved command ID {command_id}")
        response_opcode = command_id | transport["response_opcode_mask"]
        require(response_opcode not in {
            transport["event_marker"], transport["application_error_opcode"],
        }, "DUPLICATE_ID", f"{name} response opcode collides with framing")
        require(name not in names, "DUPLICATE_ID",
                f"duplicate command name {name}")
        ids.add(command_id)
        names.add(name)
        request = _validate_fields(command["request"], enums, types,
                                   f"{label}.request")
        response = _validate_fields(command["response"], enums, types,
                                    f"{label}.response")
        asynchronous = _boolean(command["asynchronous"],
                                f"{label}.asynchronous")
        completion = _optional_string(command["completion_event"],
                                      f"{label}.completion_event")
        require((asynchronous and completion in event_names) or
                (not asynchronous and completion is None), "OPERATION",
                f"{name} completion event is inconsistent")
        allowed = _string_list(command["allowed_statuses"],
                               f"{label}.allowed_statuses", True)
        require(len(allowed) == len(set(allowed)), "DUPLICATE_ID",
                f"{name} allowed statuses contain duplicates")
        require(all(status in statuses for status in allowed), "STATUS",
                f"{name} references an unknown status")
        success = (success_rules["asynchronous_success_status"] if asynchronous
                   else success_rules["synchronous_success_status"])
        require(success in allowed, "STATUS",
                f"{name} does not allow its success status")
        require(success_rules["malformed_payload_status"] in allowed, "STATUS",
                f"{name} does not allow the malformed-payload status")
        requires_full_mtu = _boolean(command["requires_full_mtu"],
                                     f"{label}.requires_full_mtu")
        low_mtu = transport["low_mtu"]
        if requires_full_mtu:
            require(low_mtu["other_commands_status"] in allowed, "STATUS",
                    f"{name} must allow the low-MTU rejection status")
        else:
            require(command.get("response_semantic") == "link_info",
                    "TRANSPORT_MATH",
                    "only the link-info command may run below full MTU")
            low_mtu_commands.add(name)
        if asynchronous:
            require(len(response) == 1 and
                    response[0]["wire"] == transport["operation_id_wire"] and
                    response[0].get("nonzero") is True,
                    "OPERATION", f"{name} must return one nonzero operation ID")
        for key in ("request_semantic", "response_semantic"):
            if key in command:
                require(command[key] in semantics, "VALUE",
                        f"unknown semantic {command[key]}")
        request_size = transport["request_header_bytes"] + _fields_max_size(
            request, types
        )
        response_size = transport["response_header_bytes"] + _fields_max_size(
            response, types
        )
        require(request_size <= maximum and response_size <= maximum,
                "LENGTH", f"{name} exceeds the ATT value capacity")
    require(len(low_mtu_commands) == 1, "TRANSPORT_MATH",
            "exactly one link-info command must run below full MTU")


def _validate_events(protocol: dict[str, Any], types: dict[str, Any],
                     enums: dict[str, Any], transport: dict[str, Any]) -> None:
    events = _list(protocol["events"], "events", True)
    ids: set[int] = set()
    names: set[str] = set()
    semantics = {"wifi_status", "scan_result", "operation_result"}
    for index, raw in enumerate(events):
        label = f"events[{index}]"
        event = _mapping(raw, {"id", "name", "payload"},
                         {"payload_semantic"}, label)
        event_id = _integer(event["id"], f"{label}.id", 1, 255)
        name = _string(event["name"], f"{label}.name")
        require(NAME_RE.fullmatch(name) is not None, "VALUE",
                f"invalid event name: {name}")
        require(event_id not in ids and name not in names, "DUPLICATE_ID",
                f"duplicate event identity: {name}")
        ids.add(event_id)
        names.add(name)
        payload = _validate_fields(event["payload"], enums, types,
                                   f"{label}.payload")
        if "payload_semantic" in event:
            require(event["payload_semantic"] in semantics, "VALUE",
                    f"unknown semantic {event['payload_semantic']}")
        size = transport["event_header_bytes"] + _fields_max_size(payload, types)
        require(size <= transport["maximum_att_value_bytes"], "LENGTH",
                f"{name} exceeds the ATT value capacity")


def _validate_response_rules(value: Any,
                             statuses: dict[str, int]) -> dict[str, Any]:
    response = _mapping(value, {
        "synchronous_success_status", "asynchronous_success_status",
        "known_command_error_payload", "unknown_opcode_status",
        "malformed_payload_status",
        "unknown_opcode_response_opcode", "unknown_opcode_payload",
    }, set(), "wire_rules.response")
    for key in response:
        if key.endswith("status"):
            require(response[key] in statuses, "STATUS",
                    f"wire_rules.response.{key} is unknown")
    require(response["known_command_error_payload"] == "empty", "VALUE",
            "known-command error responses must have empty payloads")
    require(_integer(response["unknown_opcode_response_opcode"],
                     "wire_rules.response.unknown_opcode_response_opcode",
                     0, 255) >= 0 and
            response["unknown_opcode_payload"] == "offending_opcode",
            "VALUE", "unknown opcode error envelope is inconsistent")
    return response


def _validate_wire_rules(protocol: dict[str, Any], statuses: dict[str, int],
                         enums: dict[str, Any], transport: dict[str, Any]) -> None:
    rules = _mapping(protocol["wire_rules"], WIRE_RULE_KEYS, set(),
                     "wire_rules")
    response = _validate_response_rules(rules["response"], statuses)
    require(response["unknown_opcode_response_opcode"] ==
            transport["application_error_opcode"], "OPERATION",
            "unknown opcode envelope differs from transport")
    text = _mapping(rules["text"], {
        "ssid_encoding", "ssid_forbidden_unicode_categories",
        "ssid_normalization", "password_encoding", "password_min_octet",
        "password_max_octet", "credential_password_rules",
        "raw_64_hex_psk_supported", "text_rules",
    }, set(), "wire_rules.text")
    require(text["ssid_encoding"] == "utf8" and
            text["ssid_normalization"] == "none", "VALUE",
            "SSID text rules are inconsistent")
    _string_list(text["ssid_forbidden_unicode_categories"],
                 "wire_rules.text.ssid_forbidden_unicode_categories")
    require(text["password_encoding"] == "printable_ascii", "VALUE",
            "password encoding must be printable ASCII")
    _integer(text["password_min_octet"], "text.password_min_octet", 0, 255)
    _integer(text["password_max_octet"], "text.password_max_octet", 0, 255)
    limits = protocol["protocol"]["limits"]
    credential_commands = [
        command for command in protocol["commands"]
        if command.get("request_semantic") == "credentials"
    ]
    require(len(credential_commands) == 1, "COVERAGE",
            "credential rules require one credential command")
    credential_fields = {
        field["name"]: field for field in credential_commands[0]["request"]
    }
    require("security" in credential_fields and
            credential_fields["security"]["wire"] == "enum_u8" and
            "password" in credential_fields and
            credential_fields["password"]["wire"] == "bytes_u8" and
            credential_fields["password"]["min_bytes"] == 0 and
            credential_fields["password"].get("limit_ref") in
            limits["bindings"],
            "WIRE_TYPE", "credential semantic fields are incomplete")
    security_enum = credential_fields["security"]["enum"]
    password_binding = limits["bindings"][
        credential_fields["password"]["limit_ref"]
    ]
    password_rules = _named_mapping(
        text["credential_password_rules"],
        "wire_rules.text.credential_password_rules",
    )
    require(set(password_rules) == set(enums[security_enum]), "ENUM",
            "credential password rules must cover the security enum")
    modes: set[str] = set()
    for security_name, raw_rule in password_rules.items():
        rule_label = f"credential_password_rules.{security_name}"
        require(type(raw_rule) is dict, "TYPE",
                f"{rule_label} must be a mapping")
        mode = _string(raw_rule.get("mode"), f"{rule_label}.mode")
        modes.add(mode)
        if mode == "empty":
            _mapping(raw_rule, {"mode"}, set(), rule_label)
        elif mode == "bounded":
            rule = _mapping(raw_rule, {"mode", "minimum", "maximum"},
                            set(), rule_label)
            minimum = _string(rule["minimum"], f"{rule_label}.minimum")
            maximum = _string(rule["maximum"], f"{rule_label}.maximum")
            require(minimum == password_binding["minimum"] and
                    maximum == password_binding["maximum"] and
                    password_binding["zero_length_allowed"] and
                    0 < limits[minimum] <= limits[maximum] ==
                    credential_fields["password"]["max_bytes"],
                    "VALUE", f"{rule_label} bounds are invalid")
        else:
            fail("VALUE", f"{rule_label} has an unknown mode")
    require(modes == {"empty", "bounded"}, "COVERAGE",
            "credential rules must cover empty and bounded passwords")
    require(not _boolean(text["raw_64_hex_psk_supported"],
                         "text.raw_64_hex_psk_supported"), "VALUE",
            "raw 64-character PSKs are not supported")
    text_rules = _mapping(text["text_rules"], {"ssid", "password"}, set(),
                          "wire_rules.text.text_rules")
    ssid_rule = _mapping(text_rules["ssid"], {
        "encoding", "forbidden_unicode_categories",
    }, set(), "wire_rules.text.text_rules.ssid")
    password_rule = _mapping(text_rules["password"], {
        "encoding", "min_octet", "max_octet",
    }, set(), "wire_rules.text.text_rules.password")
    require(ssid_rule["encoding"] == text["ssid_encoding"] and
            ssid_rule["forbidden_unicode_categories"] ==
            text["ssid_forbidden_unicode_categories"], "VALUE",
            "SSID field rule differs from the text rule")
    require(password_rule["encoding"] == text["password_encoding"] and
            password_rule["min_octet"] == text["password_min_octet"] and
            password_rule["max_octet"] == text["password_max_octet"], "VALUE",
            "password field rule differs from the text rule")

    wifi_status = _mapping(rules["wifi_status"], {
        "connected_means_ipv4", "profile_ssid_empty_means_no_profile",
        "state_matrix", "profile_required_states",
        "profile_required_failures", "emitted_when_snapshot_changes",
        "delivery",
    }, set(), "wire_rules.wifi_status")
    for key in ("connected_means_ipv4",
                "profile_ssid_empty_means_no_profile",
                "emitted_when_snapshot_changes"):
        require(_boolean(wifi_status[key], f"wifi_status.{key}"), "VALUE",
                f"wifi_status.{key} must be true")
    matrix = _named_mapping(wifi_status["state_matrix"],
                            "wifi_status.state_matrix")
    require(set(matrix) == set(enums["wifi_state"]), "ENUM",
            "Wi-Fi state matrix must cover every state")
    for state, failures in matrix.items():
        values = _string_list(failures, f"wifi_status.state_matrix.{state}", True)
        require(all(item in enums["wifi_failure"] for item in values), "ENUM",
                f"{state} references an unknown failure")
    for key in ("profile_required_states", "profile_required_failures"):
        values = _string_list(wifi_status[key], f"wifi_status.{key}")
        enum_name = "wifi_state" if key.endswith("states") else "wifi_failure"
        require(all(item in enums[enum_name] for item in values), "ENUM",
                f"wifi_status.{key} references an unknown value")
    delivery = _mapping(wifi_status["delivery"], {
        "ordinary_updates", "duplicate_updates",
        "pending_updates_on_disconnect", "authoritative_query",
        "final_update_latched", "terminal_event_priority",
        "ordinary_updates_while_terminal_pending",
    }, set(), "wire_rules.wifi_status.delivery")
    status_queries = {item["name"] for item in protocol["commands"]
                      if item.get("response_semantic") == "wifi_status"}
    require(delivery["ordinary_updates"] == "latest_only" and
            delivery["duplicate_updates"] == "coalesce" and
            delivery["pending_updates_on_disconnect"] == "discard" and
            delivery["authoritative_query"] in status_queries and
            _boolean(delivery["final_update_latched"],
                     "wifi_status.delivery.final_update_latched") and
            _boolean(delivery["terminal_event_priority"],
                     "wifi_status.delivery.terminal_event_priority") and
            delivery["ordinary_updates_while_terminal_pending"] == "defer",
            "OPERATION", "Wi-Fi status delivery policy is inconsistent")

    scan = _mapping(rules["scan_result"], {
        "scan_operation",
        "success_failure", "failure_values", "failure_has_empty_results",
        "maximum_records", "representable_security",
        "unsupported_security_policy", "empty_ssid_policy",
        "count_after_filter",
    }, set(), "wire_rules.scan_result")
    require(scan["success_failure"] in enums["wifi_failure"], "ENUM",
            "scan success failure is unknown")
    scan_failures = _string_list(scan["failure_values"],
                                 "scan_result.failure_values", True)
    require(len(scan_failures) == len(set(scan_failures)), "DUPLICATE_ID",
            "scan failures contain duplicates")
    require(all(item in enums["wifi_failure"] for item in scan_failures),
            "ENUM", "scan failure value is unknown")
    require(_boolean(scan["failure_has_empty_results"],
                     "scan_result.failure_has_empty_results"), "VALUE",
            "failed scans must have empty results")
    require(_integer(scan["maximum_records"],
                     "scan_result.maximum_records", 0, 255) ==
            protocol["protocol"]["limits"]["max_scan_networks"], "VALUE",
            "scan result maximum differs from the declared limit")
    require(scan["scan_operation"] in enums["operation"], "ENUM",
            "scan operation is unknown")
    security_names = list(enums["wifi_security"])
    require(enums["wifi_security"] == {"OPEN": 1, "PERSONAL": 2}, "ENUM",
            "v1 Wi-Fi security enum must be OPEN=1 and PERSONAL=2")
    representable = _mapping(scan["representable_security"],
                             set(security_names), set(),
                             "scan_result.representable_security")
    require(representable["OPEN"] == ["WIFI_AUTH_OPEN"] and
            representable["PERSONAL"] == [
                "WIFI_AUTH_WPA_PSK", "WIFI_AUTH_WPA2_PSK",
                "WIFI_AUTH_WPA_WPA2_PSK", "WIFI_AUTH_WPA3_PSK",
                "WIFI_AUTH_WPA2_WPA3_PSK",
            ], "VALUE", "Wi-Fi security mapping differs from the v1 profile")
    require(scan["unsupported_security_policy"] == "filter" and
            scan["empty_ssid_policy"] == "filter" and
            _boolean(scan["count_after_filter"],
                     "scan_result.count_after_filter"),
            "VALUE", "scan result filtering policy is inconsistent")

    operation = _mapping(rules["operation_result"], {
        "success_failure", "failure_matrix", "success_postconditions",
        "edge_cases",
    }, set(), "wire_rules.operation_result")
    require(operation["success_failure"] in enums["wifi_failure"], "ENUM",
            "operation success failure is unknown")
    failure_matrix = _named_mapping(operation["failure_matrix"],
                                    "operation_result.failure_matrix")
    postconditions = _named_mapping(operation["success_postconditions"],
                                    "operation_result.success_postconditions")
    operations = set(enums["operation"])
    non_scan_operations = operations - {scan["scan_operation"]}
    require(set(failure_matrix) == operations and
            set(postconditions) == non_scan_operations, "OPERATION",
            "operation result rules must cover every operation")
    commands_by_name = _command_maps(protocol)[1]
    events_by_name = _event_maps(protocol)[1]
    require(operations <= set(commands_by_name), "OPERATION",
            "operation enum does not reference asynchronous commands")
    for operation_name in operations:
        completion_name = commands_by_name[operation_name]["completion_event"]
        expected_semantic = ("scan_result" if operation_name ==
                             scan["scan_operation"] else "operation_result")
        require(completion_name in events_by_name and
                events_by_name[completion_name].get("payload_semantic") ==
                expected_semantic,
                "OPERATION",
                f"{operation_name} completion event semantic is inconsistent")
    for name, failures in failure_matrix.items():
        values = _string_list(failures,
                              f"operation_result.failure_matrix.{name}", True)
        require(len(values) == len(set(values)), "DUPLICATE_ID",
                f"{name} failure matrix contains duplicates")
        require(operation["success_failure"] in values and
                all(item in enums["wifi_failure"] for item in values), "ENUM",
                f"{name} references an unknown failure")
    require(failure_matrix[scan["scan_operation"]] ==
            [scan["success_failure"], *scan_failures], "OPERATION",
            "scan failure rules differ from the operation matrix")
    for name, condition in postconditions.items():
        _string(condition, f"operation_result.success_postconditions.{name}")
    edge_cases = _mapping(operation["edge_cases"], {
        "set_credentials_while_connected", "connect_without_profile",
        "forget_without_profile", "disconnect_when_idle",
        "connect_authmode_mismatch",
    }, set(), "operation_result.edge_cases")
    for name, raw_edge in edge_cases.items():
        edge = _mapping(raw_edge, {
            "command", "condition", "immediate_status", "creates_operation",
            "observable_result",
        }, {"terminal_failure"}, f"operation_result.edge_cases.{name}")
        command_name = _string(edge["command"],
                               f"operation_result.edge_cases.{name}.command")
        _string(edge["condition"],
                f"operation_result.edge_cases.{name}.condition")
        status = _string(edge["immediate_status"],
                         f"operation_result.edge_cases.{name}.immediate_status")
        require(command_name in commands_by_name and
                command_name in operations and
                status in commands_by_name[command_name]["allowed_statuses"],
                "STATUS", f"{name} references an unsupported command status")
        creates_operation = _boolean(
            edge["creates_operation"],
            f"operation_result.edge_cases.{name}.creates_operation",
        )
        require(creates_operation ==
                (status == rules["response"]["asynchronous_success_status"]),
                "OPERATION", f"{name} operation creation is inconsistent")
        _string(edge["observable_result"],
                f"operation_result.edge_cases.{name}.observable_result")
        if "terminal_failure" in edge:
            terminal_failure = _string(
                edge["terminal_failure"],
                f"operation_result.edge_cases.{name}.terminal_failure",
            )
            require(terminal_failure in failure_matrix[command_name], "ENUM",
                    f"{name} terminal failure is not allowed")

    record = _mapping(rules["operation_record"], {
        "active_phase", "succeeded_phase", "failed_phase",
        "active_failure", "active_result_count", "succeeded_failure",
        "failed_result_count", "failure_matrix_ref", "non_scan_result_count",
        "scan_results_phase",
    }, set(), "wire_rules.operation_record")
    for key in ("active_failure", "succeeded_failure"):
        require(record[key] in enums["wifi_failure"], "ENUM",
                f"operation_record.{key} is unknown")
    phases = [record["active_phase"], record["succeeded_phase"],
              record["failed_phase"]]
    require(set(phases) == set(enums["operation_phase"]) and
            len(phases) == len(set(phases)), "ENUM",
            "operation record phases must cover the phase enum")
    require(record["active_failure"] == record["succeeded_failure"] ==
            operation["success_failure"], "OPERATION",
            "active and successful records must use the success failure value")
    for key in ("active_result_count", "failed_result_count",
                "non_scan_result_count"):
        require(_integer(record[key], f"operation_record.{key}", 0, 255) == 0,
                "OPERATION", f"operation_record.{key} must be zero")
    require(record["failure_matrix_ref"] == "operation_result.failure_matrix",
            "OPERATION", "operation record must use the operation failure matrix")
    require(record["scan_results_phase"] == record["succeeded_phase"],
            "OPERATION", "scan results must appear only after success")

    lifecycle = _mapping(rules["operation_lifecycle"], {
        "accepted_commands", "accepted_response_field", "slot_capacity",
        "slot_scope", "operation_id_scope", "operation_id_exhausted_status",
        "must_reach_terminal", "finite_termination_required",
        "termination_timeout", "timeout_failure",
        "terminal_event_generated_once",
        "new_operation_while_active_status",
        "new_operation_while_terminal_status", "get_operation_no_record_status",
        "ack_active_status", "ack_before_terminal_event_status",
        "ack_missing_or_mismatch_status",
        "ack_terminal_clears_record", "disconnect_clears_record",
        "accepted_response_disconnect_policy",
        "reconnect_query", "reconnect_status_query", "terminal_event_replay",
        "reboot_clears_record", "ack_requires_terminal_event_confirmation",
        "ack_clears_after_response_confirmation",
        "reconnect_ack_without_replay",
    }, set(), "wire_rules.operation_lifecycle")
    accepted = _string_list(lifecycle["accepted_commands"],
                            "operation_lifecycle.accepted_commands", True)
    async_names = {item["name"] for item in protocol["commands"]
                   if item["asynchronous"]}
    require(set(accepted) == async_names, "OPERATION",
            "operation lifecycle must cover every async command")
    commands_by_name = _command_maps(protocol)[1]
    for command_name in async_names:
        allowed_statuses = commands_by_name[command_name]["allowed_statuses"]
        require(all(lifecycle[key] in allowed_statuses for key in (
            "new_operation_while_active_status",
            "new_operation_while_terminal_status",
            "operation_id_exhausted_status",
        )), "STATUS", f"{command_name} omits an operation lifecycle status")
        require(lifecycle["timeout_failure"] in
                rules["operation_result"]["failure_matrix"][command_name],
                "OPERATION", f"{command_name} omits the timeout failure")
    require(set(enums["operation"]) == async_names and
            all(enums["operation"][name] == commands_by_name[name]["id"]
                for name in async_names), "OPERATION",
            "operation enum must match asynchronous command identities")
    require(lifecycle["accepted_response_field"] == "operation_id",
            "OPERATION", "async responses must return operation_id")
    require(all([field["name"] for field in commands_by_name[name]["response"]] ==
                [lifecycle["accepted_response_field"]]
                for name in async_names), "OPERATION",
            "asynchronous response fields differ from the lifecycle rule")
    require(_integer(lifecycle["slot_capacity"],
                     "operation_lifecycle.slot_capacity") == 1 and
            lifecycle["slot_scope"] == "device" and
            lifecycle["operation_id_scope"] == "boot", "OPERATION",
            "operation slot scope is inconsistent")
    require(_boolean(lifecycle["finite_termination_required"],
                     "operation_lifecycle.finite_termination_required") and
            lifecycle["termination_timeout"] ==
            "implementation_defined_finite" and
            lifecycle["timeout_failure"] in enums["wifi_failure"],
            "OPERATION", "accepted operations require a finite timeout")
    require(lifecycle["accepted_response_disconnect_policy"] ==
            "discard_and_query", "OPERATION",
            "unconfirmed accepted responses must recover by query")
    for key in (
        "new_operation_while_active_status",
        "new_operation_while_terminal_status", "get_operation_no_record_status",
        "ack_active_status", "ack_before_terminal_event_status",
        "ack_missing_or_mismatch_status",
        "operation_id_exhausted_status",
    ):
        require(lifecycle[key] in statuses, "STATUS",
                f"operation_lifecycle.{key} is unknown")
    require(_boolean(lifecycle["ack_terminal_clears_record"],
                     "operation_lifecycle.ack_terminal_clears_record") and
            not _boolean(lifecycle["disconnect_clears_record"],
                         "operation_lifecycle.disconnect_clears_record") and
            not _boolean(lifecycle["terminal_event_replay"],
                         "operation_lifecycle.terminal_event_replay") and
            _boolean(lifecycle["reboot_clears_record"],
                     "operation_lifecycle.reboot_clears_record"),
            "OPERATION", "operation retention rules are inconsistent")
    for key in ("must_reach_terminal", "terminal_event_generated_once",
                "ack_requires_terminal_event_confirmation",
                "ack_clears_after_response_confirmation",
                "reconnect_ack_without_replay"):
        require(_boolean(lifecycle[key], f"operation_lifecycle.{key}"),
                "OPERATION", f"operation_lifecycle.{key} must be true")
    operation_queries = {item["name"] for item in protocol["commands"]
                         if item.get("response_semantic") == "operation_record"}
    status_queries = {item["name"] for item in protocol["commands"]
                      if item.get("response_semantic") == "wifi_status"}
    require({lifecycle["reconnect_query"]} == operation_queries and
            {lifecycle["reconnect_status_query"]} == status_queries,
            "OPERATION", "reconnect recovery queries are inconsistent")
    operation_query = commands_by_name[lifecycle["reconnect_query"]]
    require(lifecycle["get_operation_no_record_status"] in
            operation_query["allowed_statuses"], "STATUS",
            "operation query omits the no-record status")
    ack_commands = [item for item in protocol["commands"]
                    if [field["name"] for field in item["request"]] ==
                    [lifecycle["accepted_response_field"]] and
                    not item["response"]]
    require(len(ack_commands) == 1 and all(
        lifecycle[key] in ack_commands[0]["allowed_statuses"] for key in (
            "ack_active_status", "ack_before_terminal_event_status",
            "ack_missing_or_mismatch_status",
        )
    ), "STATUS", "operation ACK omits a lifecycle status")
    read_queries = {
        item["name"] for item in protocol["commands"]
        if item.get("response_semantic") in {
            "link_info", "wifi_status", "operation_record",
        }
    }
    control_commands = {item["name"] for item in ack_commands}
    synchronous_names = {item["name"] for item in protocol["commands"]
                         if not item["asynchronous"]}
    require(set(transport["operation_slot_queries"]) == read_queries and
            set(transport["operation_slot_controls"]) == control_commands and
            read_queries | control_commands == synchronous_names,
            "OPERATION",
            "operation slot query/control groups are inconsistent")
    require(transport["operation_slot_commands"] == accepted and
            transport["operation_slot_capacity"] == lifecycle["slot_capacity"] and
            transport["operation_id_scope"] == lifecycle["operation_id_scope"] and
            transport["operation_slot_occupied_status"] ==
            lifecycle["new_operation_while_active_status"] ==
            lifecycle["new_operation_while_terminal_status"] ==
            lifecycle["ack_active_status"] ==
            lifecycle["ack_before_terminal_event_status"] and
            transport["operation_id_exhausted_status"] ==
            lifecycle["operation_id_exhausted_status"], "OPERATION",
            "transport and lifecycle operation rules differ")

    sequencing = _mapping(rules["sequencing"], {
        "accepted_response_confirmation_precedes_terminal_event",
        "final_status_confirmation_precedes_terminal_event_if_changed",
        "ack_response_confirmation_precedes_record_clear",
        "terminal_events",
    }, set(), "wire_rules.sequencing")
    require(_boolean(
        sequencing["accepted_response_confirmation_precedes_terminal_event"],
        "sequencing.accepted_response_confirmation_precedes_terminal_event",
    ), "OPERATION", "accepted response must precede terminal delivery")
    require(_boolean(
        sequencing["final_status_confirmation_precedes_terminal_event_if_changed"],
        "sequencing.final_status_confirmation_precedes_terminal_event_if_changed",
    ), "OPERATION", "final status must precede terminal delivery")
    require(_boolean(
        sequencing["ack_response_confirmation_precedes_record_clear"],
        "sequencing.ack_response_confirmation_precedes_record_clear",
    ), "OPERATION", "ACK response confirmation must precede record removal")
    terminal_events = _named_mapping(sequencing["terminal_events"],
                                     "sequencing.terminal_events")
    require(set(terminal_events) == async_names, "OPERATION",
            "terminal event mapping must cover every async command")
    _, events_by_name = _event_maps(protocol)
    for command_name, event_name in terminal_events.items():
        require(event_name in events_by_name and
                commands_by_name[command_name]["completion_event"] == event_name,
                "OPERATION", f"terminal event mismatch for {command_name}")
        event_fields = events_by_name[event_name]["payload"]
        operation_id_fields = [field for field in event_fields
                               if field["name"] ==
                               lifecycle["accepted_response_field"]]
        require(len(operation_id_fields) == 1 and
                operation_id_fields[0]["wire"] == transport["operation_id_wire"] and
                operation_id_fields[0].get("nonzero") is True,
                "OPERATION", f"{event_name} must carry a nonzero operation ID")
        if len({name for name, mapped in terminal_events.items()
                if mapped == event_name}) > 1:
            operation_fields = [field for field in event_fields
                                if field["name"] == "operation"]
            require(len(operation_fields) == 1 and
                    operation_fields[0].get("enum") == "operation",
                    "OPERATION", f"{event_name} must identify its operation")


def _validate_declared_sizes(protocol: dict[str, Any], types: dict[str, Any]) -> None:
    transport = protocol["protocol"]["transport"]
    limits = protocol["protocol"]["limits"]
    info = [item for item in protocol["commands"]
            if item.get("response_semantic") == "link_info"]
    records = [item for item in protocol["commands"]
               if item.get("response_semantic") == "operation_record"]
    scans = [item for item in protocol["events"]
             if item.get("payload_semantic") == "scan_result"]
    require(len(info) == len(records) == len(scans) == 1, "COVERAGE",
            "size anchors require one link-info, operation-record, and scan event")
    info_size = transport["response_header_bytes"] + _fields_max_size(
        info[0]["response"], types
    )
    record_size = transport["response_header_bytes"] + _fields_max_size(
        records[0]["response"], types
    )
    scan_size = transport["event_header_bytes"] + _fields_max_size(
        scans[0]["payload"], types
    )
    require(info_size == limits["maximum_get_info_response_bytes"] and
            record_size == limits["maximum_get_operation_response_bytes"] and
            scan_size == limits["maximum_scan_event_bytes"],
            "TRANSPORT_MATH", "declared maximum message sizes are inconsistent")
    require(info_size <= transport["minimum_att_mtu"] -
            transport["att_value_header_bytes"], "TRANSPORT_MATH",
            "the link-info response must fit the default ATT MTU")


def validate_protocol(protocol: dict[str, Any]) -> None:
    root = _mapping(protocol, {
        "schema_version", "profile", "protocol", "wire_types", "types",
        "status_codes", "enums", "commands", "events", "wire_rules",
    }, set(), "protocol")
    require(_integer(root["schema_version"], "schema_version") == 1, "VALUE",
            "schema_version must be 1")
    profile = _mapping(root["profile"], {
        "name", "schema_format", "version", "release_state",
    }, set(), "profile")
    _string(profile["name"], "profile.name")
    _string(profile["schema_format"], "profile.schema_format")
    require(SEMVER_RE.fullmatch(_string(profile["version"],
                                       "profile.version")) is not None,
            "VERSION", "profile version must be semantic x.y.z")
    _string(profile["release_state"], "profile.release_state")
    _validate_wire_types(root["wire_types"])

    data = _mapping(root["protocol"], {
        "name", "major", "minor", "byte_order", "gatt", "security",
        "transport", "att_errors", "limits",
    }, set(), "protocol.protocol")
    _string(data["name"], "protocol.name")
    _integer(data["major"], "protocol.major", 0, 255)
    _integer(data["minor"], "protocol.minor", 0, 255)
    require(data["byte_order"] == "little", "VALUE",
            "fixed-binary integers must be little endian")
    gatt = _validate_gatt(data["gatt"])
    _validate_security(data["security"])
    transport = _validate_transport(data["transport"])
    _validate_att_errors(data["att_errors"])
    limits = _validate_limits(data["limits"])
    require(limits["min_ssid_bytes"] <= limits["max_ssid_bytes"] <= 255 and
            limits["min_personal_password_bytes"] <=
            limits["max_personal_password_bytes"] <= 255,
            "VALUE", "text limits are inconsistent")
    for characteristic in gatt["characteristics"].values():
        require(characteristic["max_value_bytes"] ==
                transport["maximum_att_value_bytes"], "TRANSPORT_MATH",
                "GATT characteristic capacity differs from transport")

    statuses = _validate_number_registry(root["status_codes"], "status_codes")
    enums_raw = _named_mapping(root["enums"], "enums")
    enums = {
        name: _validate_number_registry(value, f"enums.{name}")
        for name, value in enums_raw.items()
    }
    types = _named_mapping(root["types"], "types")
    for name, raw_type in types.items():
        definition = _mapping(raw_type, {"fields"}, set(), f"types.{name}")
        _validate_fields(definition["fields"], enums, types,
                         f"types.{name}.fields")
    scan_fields = types["scan_network"]["fields"]
    rssi_fields = [field for field in scan_fields
                   if field["name"] == "rssi_dbm"]
    require(len(rssi_fields) == 1 and rssi_fields[0]["wire"] == "i8" and
            rssi_fields[0]["min"] == -127 and
            rssi_fields[0]["max"] == 127, "VALUE",
            "scan RSSI must use the -127..127 i8 range")

    require(type(root["commands"]) is list and type(root["events"]) is list,
            "TYPE", "commands and events must be lists")
    wire_rules = _mapping(root["wire_rules"], WIRE_RULE_KEYS, set(),
                          "wire_rules")
    success_rules = _validate_response_rules(wire_rules["response"], statuses)
    _validate_events(protocol, types, enums, transport)
    _validate_commands(protocol, types, enums, statuses, transport,
                       success_rules)
    _validate_wire_rules(protocol, statuses, enums, transport)
    _validate_field_rule_links(protocol, limits)
    _validate_declared_sizes(protocol, types)


def validate_version(protocol: dict[str, Any],
                     path: Path = VERSION_PATH) -> None:
    expected = protocol["profile"]["version"] + "\n"
    try:
        actual = path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise ContractError("VERSION", f"cannot read VERSION: {exc}") from exc
    require(actual == expected, "VERSION",
            "VERSION must exactly match profile.version with one newline")


def validate_att_value_length(protocol: dict[str, Any], length: int) -> None:
    maximum = protocol["protocol"]["transport"]["maximum_att_value_bytes"]
    require(_is_int(length) and 0 <= length <= maximum,
            "ATT_VALUE_TOO_LONG", f"ATT value length {length} exceeds {maximum}")


def _enum_name(protocol: dict[str, Any], enum_name: str, number: int,
               label: str) -> str:
    mapping = protocol["enums"][enum_name]
    for name, value in mapping.items():
        if value == number:
            return name
    fail("ENUM", f"{label} has unknown {enum_name} value {number}")


def _read(data: bytes, offset: int, count: int, label: str) -> tuple[bytes, int]:
    require(offset + count <= len(data), "LENGTH", f"{label} is truncated")
    return data[offset:offset + count], offset + count


def _decode_fields(protocol: dict[str, Any], fields: list[dict[str, Any]],
                   data: bytes, label: str) -> dict[str, Any]:
    values: dict[str, Any] = {}
    offset = 0
    for field in fields:
        name = field["name"]
        wire = field["wire"]
        field_label = f"{label}.{name}"
        if wire in {"u8", "bool", "enum_u8", "i8"}:
            raw, offset = _read(data, offset, 1, field_label)
            number = raw[0]
            if wire == "i8":
                number = number - 256 if number >= 128 else number
                require(field["min"] <= number <= field["max"], "VALUE",
                        f"{field_label} is out of range")
                values[name] = number
            elif wire == "bool":
                require(number in (0, 1), "BOOL",
                        f"{field_label} is not a bool")
                values[name] = bool(number)
            elif wire == "enum_u8":
                values[name] = _enum_name(
                    protocol, field["enum"], number, field_label
                )
            else:
                if field.get("nonzero", False):
                    require(number != 0, "VALUE", f"{field_label} must be nonzero")
                values[name] = number
        elif wire in {"u16", "u32"}:
            count = 2 if wire == "u16" else 4
            raw, offset = _read(data, offset, count, field_label)
            number = int.from_bytes(raw, "little")
            if field.get("nonzero", False):
                require(number != 0, "VALUE", f"{field_label} must be nonzero")
            values[name] = number
        elif wire == "bytes_u8":
            raw_length, offset = _read(data, offset, 1, field_label)
            count = raw_length[0]
            require(field["min_bytes"] <= count <= field["max_bytes"],
                    "LENGTH", f"{field_label} length is out of range")
            raw, offset = _read(data, offset, count, field_label)
            text_rule = protocol["wire_rules"]["text"]["text_rules"][
                field["text_rule"]
            ]
            if text_rule["encoding"] == "utf8":
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ContractError("UTF8", f"{field_label} is invalid") from exc
                forbidden = set(text_rule["forbidden_unicode_categories"])
                require(not any(unicodedata.category(char) in forbidden
                                for char in text), "UTF8",
                        f"{field_label} contains a forbidden character")
            elif text_rule["encoding"] == "printable_ascii":
                require(all(text_rule["min_octet"] <= item <=
                            text_rule["max_octet"] for item in raw), "TEXT",
                        f"{field_label} is not printable ASCII")
            values[name] = raw
        elif wire == "repeated":
            count = values[field["count_field"]]
            require(count <= field["max_count"], "LENGTH",
                    f"{field_label} count exceeds its maximum")
            records = []
            item_fields = protocol["types"][field["item_type"]]["fields"]
            for index in range(count):
                start = offset
                item_data = data[offset:]
                record, consumed = _decode_fields_partial(
                    protocol, item_fields, item_data,
                    f"{field_label}[{index}]",
                )
                require(consumed > 0, "LENGTH", f"{field_label} made no progress")
                offset = start + consumed
                records.append(record)
            values[name] = records
        else:
            fail("WIRE_TYPE", f"cannot decode {wire}")
    require(offset == len(data), "LENGTH", f"{label} has trailing bytes")
    return values


def _decode_fields_partial(protocol: dict[str, Any],
                           fields: list[dict[str, Any]], data: bytes,
                           label: str) -> tuple[dict[str, Any], int]:
    for length in range(1, len(data) + 1):
        try:
            values = _decode_fields(protocol, fields, data[:length], label)
        except ContractError as exc:
            if exc.code == "LENGTH":
                continue
            raise
        return values, length
    fail("LENGTH", f"{label} is truncated")


def _apply_semantic(protocol: dict[str, Any], semantic: str | None,
                    values: dict[str, Any], label: str) -> None:
    if semantic is None:
        return
    rules = protocol["wire_rules"]
    if semantic == "credentials":
        security = values["security"]
        password = values["password"]
        password_rule = rules["text"]["credential_password_rules"][security]
        if password_rule["mode"] == "empty":
            require(len(password) == 0, "VALUE",
                    f"{label} password must be empty for this security mode")
        elif password_rule["mode"] == "bounded":
            limits = protocol["protocol"]["limits"]
            minimum = limits[password_rule["minimum"]]
            maximum = limits[password_rule["maximum"]]
            require(minimum <= len(password) <= maximum, "VALUE",
                    f"{label} password length is invalid for this security mode")
    elif semantic == "link_info":
        data = protocol["protocol"]
        require(values["protocol_major"] == data["major"] and
                values["protocol_minor"] == data["minor"], "VERSION",
                f"{label} protocol version differs")
        require(values["required_att_mtu"] ==
                data["transport"]["required_att_mtu"], "TRANSPORT_MATH",
                f"{label} required ATT MTU differs")
    elif semantic == "wifi_status":
        rule = rules["wifi_status"]
        require(values["failure"] in rule["state_matrix"][values["state"]],
                "VALUE", f"{label} state/failure combination is invalid")
        requires_profile = (
            values["state"] in rule["profile_required_states"] or
            values["failure"] in rule["profile_required_failures"]
        )
        require(not requires_profile or len(values["profile_ssid"]) > 0,
                "VALUE", f"{label} requires a profile SSID")
    elif semantic == "scan_result":
        rule = rules["scan_result"]
        allowed = {rule["success_failure"], *rule["failure_values"]}
        require(values["failure"] in allowed, "VALUE",
                f"{label} scan failure is invalid")
        require(values["count"] == len(values["networks"]), "LENGTH",
                f"{label} scan count differs")
        if values["failure"] != rule["success_failure"]:
            require(values["count"] == 0, "VALUE",
                    f"{label} failed scan must have no results")
    elif semantic == "operation_result":
        matrix = rules["operation_result"]["failure_matrix"]
        result_events = {item["name"] for item in protocol["events"]
                         if item.get("payload_semantic") == "operation_result"}
        allowed_operations = {
            item["name"] for item in protocol["commands"]
            if item.get("completion_event") in result_events
        }
        require(values["operation"] in allowed_operations and
                values["operation"] in matrix and
                values["failure"] in matrix[values["operation"]], "VALUE",
                f"{label} operation/failure combination is invalid")
    elif semantic == "operation_record":
        rule = rules["operation_record"]
        phase = values["phase"]
        operation = values["operation"]
        failure = values["failure"]
        count = values["count"]
        require(count == len(values["networks"]), "LENGTH",
                f"{label} operation result count differs")
        if phase == rule["active_phase"]:
            require(failure == rule["active_failure"] and
                    count == rule["active_result_count"], "VALUE",
                    f"{label} active operation record is invalid")
        elif phase == rule["succeeded_phase"]:
            require(failure == rule["succeeded_failure"], "VALUE",
                    f"{label} successful operation has a failure")
        elif phase == rule["failed_phase"]:
            allowed_failures = rules["operation_result"]["failure_matrix"].get(
                operation, []
            )
            require(failure != rule["succeeded_failure"] and
                    failure in allowed_failures and
                    count == rule["failed_result_count"],
                    "VALUE", f"{label} failed operation record is invalid")
        scan_operation = rules["scan_result"]["scan_operation"]
        if operation != scan_operation:
            require(count == rule["non_scan_result_count"], "VALUE",
                    f"{label} non-scan operation has scan results")
        if count > 0:
            require(operation == scan_operation and
                    phase == rule["scan_results_phase"],
                    "VALUE", f"{label} scan results appear in the wrong phase")
    else:
        fail("VALUE", f"unknown semantic: {semantic}")


def _message_shape(case: Any) -> dict[str, Any]:
    require(type(case) is dict, "TYPE", "message case must be a mapping")
    kind = case.get("kind")
    require(type(kind) is str, "TYPE", "message kind must be a string")
    if kind == "request":
        required = {"id", "kind", "name", "request_id", "hex"}
    elif kind == "response":
        required = {"id", "kind", "name", "request_id", "status", "hex"}
    elif kind == "event":
        required = {"id", "kind", "name", "hex"}
    elif kind == "application_error":
        required = {
            "id", "kind", "request_id", "status", "offending_opcode", "hex",
        }
    else:
        fail("VALUE", f"unknown message kind: {kind}")
    return _mapping(case, required, set(), f"message {case.get('id', '?')}")


def validate_message(protocol: dict[str, Any], case: Any) -> dict[str, Any]:
    item = _message_shape(case)
    label = _string(item["id"], "message.id")
    raw = _hex(item["hex"], f"{label}.hex")
    validate_att_value_length(protocol, len(raw))
    transport = protocol["protocol"]["transport"]
    command_by_id, command_by_name = _command_maps(protocol)
    event_by_name = _event_maps(protocol)[1]
    kind = item["kind"]
    if kind == "application_error":
        require(len(raw) == 4, "LENGTH",
                f"{label} application error must be four bytes")
        request_id = _integer(item["request_id"], f"{label}.request_id", 0, 255)
        require(transport["request_id_min"] <= request_id <=
                transport["request_id_max"], "VALUE",
                f"{label} request ID is reserved")
        offending_opcode = _integer(item["offending_opcode"],
                                    f"{label}.offending_opcode", 0, 255)
        status_name = _string(item["status"], f"{label}.status")
        response_rule = protocol["wire_rules"]["response"]
        require(status_name == response_rule["unknown_opcode_status"], "STATUS",
                f"{label} application error status is invalid")
        require(offending_opcode < transport["response_opcode_mask"] and
                (offending_opcode in transport["reserved_request_opcodes"] or
                 offending_opcode not in command_by_id), "MESSAGE",
                f"{label} offending opcode is not unknown or reserved")
        expected = bytes((
            transport["application_error_opcode"], request_id,
            protocol["status_codes"][status_name], offending_opcode,
        ))
        require(raw == expected, "MESSAGE",
                f"{label} application error envelope is inconsistent")
        return {"offending_opcode": offending_opcode}

    name = _string(item["name"], f"{label}.name")
    if kind in {"request", "response"}:
        require(name in command_by_name, "MESSAGE", f"unknown command {name}")
        command = command_by_name[name]
        header_size = (transport["request_header_bytes"] if kind == "request"
                       else transport["response_header_bytes"])
        require(len(raw) >= header_size, "LENGTH", f"{label} header is truncated")
        request_id = _integer(item["request_id"], f"{label}.request_id", 0, 255)
        require(transport["request_id_min"] <= request_id <=
                transport["request_id_max"], "VALUE",
                f"{label} request ID is reserved")
        expected_opcode = command["id"]
        if kind == "response":
            expected_opcode |= transport["response_opcode_mask"]
        require(raw[0] == expected_opcode and raw[1] == request_id, "MESSAGE",
                f"{label} header does not match its metadata")
        if kind == "request":
            values = _decode_fields(protocol, command["request"], raw[2:], label)
            _apply_semantic(protocol, command.get("request_semantic"), values,
                            label)
            return values
        status_name = _string(item["status"], f"{label}.status")
        require(status_name in protocol["status_codes"], "STATUS",
                f"{label} status is unknown")
        require(status_name in command["allowed_statuses"], "STATUS",
                f"{label} status is not allowed for {name}")
        require(raw[2] == protocol["status_codes"][status_name], "STATUS",
                f"{label} status byte differs from metadata")
        success = (protocol["wire_rules"]["response"]
                   ["asynchronous_success_status"] if command["asynchronous"]
                   else protocol["wire_rules"]["response"]
                   ["synchronous_success_status"])
        if status_name != success:
            require(len(raw) == header_size, "LENGTH",
                    f"{label} error response has a payload")
            return {}
        values = _decode_fields(protocol, command["response"], raw[3:], label)
        _apply_semantic(protocol, command.get("response_semantic"), values,
                        label)
        return values

    require(name in event_by_name, "MESSAGE", f"unknown event {name}")
    event = event_by_name[name]
    require(len(raw) >= transport["event_header_bytes"], "LENGTH",
            f"{label} header is truncated")
    require(raw[0] == transport["event_marker"] and raw[1] == event["id"],
            "MESSAGE", f"{label} event header differs from metadata")
    values = _decode_fields(protocol, event["payload"], raw[2:], label)
    _apply_semantic(protocol, event.get("payload_semantic"), values, label)
    return values


def _validate_routing_case(protocol: dict[str, Any], case: Any) -> str:
    item = _mapping(case, {
        "id", "opcode", "request_id", "att_mtu", "att_value_length",
        "encrypted", "authenticated", "subscription_enabled",
        "indication_outstanding", "payload_valid", "slot_occupied", "expect",
    }, {"conditions"}, "routing case")
    label = _string(item["id"], "routing_case.id")
    transport = protocol["protocol"]["transport"]
    opcode = _integer(item["opcode"], f"{label}.opcode", 0, 255)
    request_id = _integer(item["request_id"], f"{label}.request_id", 0, 255)
    att_mtu = _integer(item["att_mtu"], f"{label}.att_mtu",
                       transport["minimum_att_mtu"])
    value_length = _integer(item["att_value_length"],
                            f"{label}.att_value_length", 0)
    flags = {
        key: _boolean(item[key], f"{label}.{key}")
        for key in (
            "encrypted", "authenticated", "subscription_enabled",
            "indication_outstanding", "payload_valid", "slot_occupied",
        )
    }
    conditions = _string_list(item.get("conditions", []),
                              f"{label}.conditions")
    require(len(conditions) == len(set(conditions)), "DUPLICATE_ID",
            f"{label} conditions contain duplicates")
    edge_cases = protocol["wire_rules"]["operation_result"]["edge_cases"]
    declared_conditions = {edge["condition"] for edge in edge_cases.values()}
    require(set(conditions) <= declared_conditions, "OPERATION",
            f"{label} references an unknown observable condition")
    att_errors = protocol["protocol"]["att_errors"]
    gatt_failures = {
        "security_gate": (not flags["encrypted"] or
                           not flags["authenticated"],
                           att_errors["security_gate_error"]),
        "att_value_length": (
            value_length > transport["maximum_att_value_bytes"],
            "invalid_attribute_value_length",
        ),
        "header_values": (
            value_length < transport["request_header_bytes"] or
            (transport["request_opcode_msb_must_be_zero"] and
             opcode >= transport["response_opcode_mask"]) or
            not transport["request_id_min"] <= request_id <=
            transport["request_id_max"],
            "value_not_allowed",
        ),
        "server_tx_subscription": (not flags["subscription_enabled"],
                                   "profile_cccd_not_enabled"),
        "unconfirmed_server_tx": (flags["indication_outstanding"],
                                  "profile_tx_indication_pending"),
    }
    actual = ""
    feature = ""
    for check in att_errors["gatt_precedence"]:
        failed, error_name = gatt_failures[check]
        if failed:
            actual = f"ATT:{error_name}"
            feature = check
            break

    command = _command_maps(protocol)[0].get(opcode)
    if not actual:
        response = protocol["wire_rules"]["response"]
        low_mtu = transport["low_mtu"]
        for check in att_errors["application_precedence"]:
            if check == "unknown_opcode":
                if (opcode in transport["reserved_request_opcodes"] or
                        command is None):
                    actual = f"APP:{response['unknown_opcode_status']}"
                    feature = check
                    break
            elif check == "get_info_low_mtu_exception":
                if (command is not None and not command["requires_full_mtu"] and
                        att_mtu < low_mtu["full_profile_required_att_mtu"]):
                    feature = check
            elif check == "required_mtu":
                if (command is not None and command["requires_full_mtu"] and
                        att_mtu < low_mtu["full_profile_required_att_mtu"]):
                    actual = f"APP:{low_mtu['other_commands_status']}"
                    feature = check
                    break
            elif check == "payload":
                if not flags["payload_valid"]:
                    actual = f"APP:{response['malformed_payload_status']}"
                    feature = check
                    break
            elif check == "operation_slot":
                if (command is not None and command["asynchronous"] and
                        flags["slot_occupied"]):
                    actual = f"APP:{transport['operation_slot_occupied_status']}"
                    feature = check
                    break
            elif check == "observable_precondition":
                if command is not None:
                    for edge in edge_cases.values():
                        if (not edge["creates_operation"] and
                                edge["command"] == command["name"] and
                                edge["condition"] in conditions):
                            actual = f"APP:{edge['immediate_status']}"
                            feature = check
                            break
                    if actual:
                        break
    if not actual:
        actual = "ADMITTED"
        feature = feature or "admitted"
    require(actual == _string(item["expect"], f"{label}.expect"),
            "EXPECTATION", f"{label} expected {item['expect']}, got {actual}")
    return feature


def _validate_operation_case(protocol: dict[str, Any], case: Any) -> set[str]:
    item = _mapping(case, {"id", "steps"}, set(), "operation case")
    label = _string(item["id"], "operation_case.id")
    steps = _list(item["steps"], f"{label}.steps", True)
    rules = protocol["wire_rules"]
    lifecycle = rules["operation_lifecycle"]
    record_rules = rules["operation_record"]
    response_rules = rules["response"]
    wifi_states = set(protocol["enums"]["wifi_state"])
    accepted = set(lifecycle["accepted_commands"])
    failure_matrix = rules["operation_result"]["failure_matrix"]
    success_failure = rules["operation_result"]["success_failure"]
    timeout_failure = lifecycle["timeout_failure"]
    accepted_status = response_rules["asynchronous_success_status"]
    ok_status = response_rules["synchronous_success_status"]
    slot: dict[str, Any] | None = None
    connected = True
    pending_indication: str | None = None
    seen_ids: set[int] = set()
    ids_exhausted = False
    features: set[str] = set()
    reconnected = False
    recovered_terminal = False
    reboot_cleared_record = False
    ordinary_pending: str | None = None
    for index, raw_step in enumerate(steps):
        step_label = f"{label}.steps[{index}]"
        require(type(raw_step) is dict, "TYPE",
                f"{step_label} must be a mapping")
        action = _string(raw_step.get("action"), f"{step_label}.action")
        if action == "accept":
            step = _mapping(raw_step, {"action", "operation", "expect"},
                            {"operation_id"}, step_label)
            require(connected, "EXPECTATION",
                    f"{step_label} cannot accept while disconnected")
            require(pending_indication is None, "EXPECTATION",
                    f"{step_label} is blocked by an outstanding indication")
            operation = _string(step["operation"], f"{step_label}.operation")
            require(operation in accepted, "OPERATION",
                    f"{step_label} operation is not asynchronous")
            expected = _string(step["expect"], f"{step_label}.expect")
            actual = (lifecycle["new_operation_while_active_status"]
                      if slot is not None and
                      slot["phase"] == record_rules["active_phase"] else
                      lifecycle["new_operation_while_terminal_status"]
                      if slot is not None else
                      lifecycle["operation_id_exhausted_status"]
                      if ids_exhausted else accepted_status)
            require(actual == expected, "EXPECTATION",
                    f"{step_label} expected {expected}, got {actual}")
            if actual == accepted_status:
                require(set(step) == {
                    "action", "operation", "operation_id", "expect",
                }, "MISSING_FIELD",
                        f"{step_label} accepted response must carry an operation ID")
                operation_id = _integer(
                    step["operation_id"], f"{step_label}.operation_id",
                    1, UINT32_MAX,
                )
                require(operation_id not in seen_ids, "OPERATION",
                        f"{step_label} reuses an operation ID in one boot")
                seen_ids.add(operation_id)
                slot = {"operation": operation, "operation_id": operation_id,
                        "phase": record_rules["active_phase"],
                        "failure": record_rules["active_failure"],
                        "accepted_confirmed": False,
                        "status_changed": False, "status_confirmed": False,
                        "terminal_event_emitted": False,
                        "terminal_event_confirmed": False,
                        "recovery_required": False}
                pending_indication = "accepted_response"
            else:
                require("operation_id" not in step, "OPERATION",
                        f"{step_label} rejected response must not allocate an ID")
                if slot is not None:
                    if slot["phase"] == record_rules["active_phase"]:
                        features.add("active_blocks_new")
                    else:
                        features.add("terminal_blocks_new")
                elif ids_exhausted:
                    features.add("id_exhaustion_empty")
        elif action == "confirm_accepted":
            step = _mapping(raw_step, {"action", "operation_id"}, set(),
                            step_label)
            operation_id = _integer(step["operation_id"],
                                    f"{step_label}.operation_id", 1, UINT32_MAX)
            require(slot is not None and
                    slot["operation_id"] == operation_id and
                    pending_indication == "accepted_response", "EXPECTATION",
                    f"{step_label} does not match the accepted response")
            slot["accepted_confirmed"] = True
            pending_indication = None
            features.add("accepted_confirmation")
        elif action == "complete":
            step = _mapping(raw_step, {
                "action", "operation_id", "failure", "status_changed",
            }, set(), step_label)
            operation_id = _integer(step["operation_id"],
                                    f"{step_label}.operation_id", 1, UINT32_MAX)
            failure = _string(step["failure"], f"{step_label}.failure")
            require(slot is not None and
                    slot["phase"] == record_rules["active_phase"] and
                    slot["operation_id"] == operation_id, "EXPECTATION",
                    f"{step_label} does not match the active operation")
            require(failure in failure_matrix[slot["operation"]], "VALUE",
                    f"{step_label} failure is invalid for the operation")
            slot["phase"] = (record_rules["succeeded_phase"]
                             if failure == success_failure else
                             record_rules["failed_phase"])
            slot["failure"] = failure
            slot["recovery_required"] |= not connected
            if failure == success_failure:
                features.add(f"succeeded:{slot['operation']}")
            elif failure != timeout_failure:
                features.add(f"failed:{slot['operation']}")
            slot["status_changed"] = _boolean(
                step["status_changed"], f"{step_label}.status_changed"
            )
            if slot["status_changed"]:
                features.add("final_status_latched")
                ordinary_pending = None
            if failure == timeout_failure:
                features.add(f"timeout:{slot['operation']}")
            authmode_edges = [edge for edge in
                              rules["operation_result"]["edge_cases"].values()
                              if "terminal_failure" in edge]
            if any(slot["operation"] == edge["command"] and
                   failure == edge["terminal_failure"]
                   for edge in authmode_edges):
                features.add("connect_authentication_failure")
        elif action == "queue_ordinary_status":
            step = _mapping(raw_step, {"action", "snapshot"}, set(),
                            step_label)
            final_latched = (slot is not None and
                             slot["phase"] != record_rules["active_phase"] and
                             slot["status_changed"] and
                             not slot["recovery_required"] and
                             not slot["status_confirmed"])
            require(connected and not final_latched,
                    "EXPECTATION",
                    f"{step_label} cannot queue an ordinary status now")
            snapshot = _string(step["snapshot"], f"{step_label}.snapshot")
            require(snapshot in wifi_states, "ENUM",
                    f"{step_label} snapshot is not a Wi-Fi state")
            if ordinary_pending == snapshot:
                features.add("status_coalesced")
            elif ordinary_pending is not None:
                features.add("status_latest_replaced")
            ordinary_pending = snapshot
        elif action == "emit_ordinary_status":
            step = _mapping(raw_step, {"action", "snapshot"}, set(),
                            step_label)
            snapshot = _string(step["snapshot"], f"{step_label}.snapshot")
            require(snapshot in wifi_states, "ENUM",
                    f"{step_label} snapshot is not a Wi-Fi state")
            require(connected and pending_indication is None and
                    not (slot is not None and
                         slot["phase"] != record_rules["active_phase"] and
                         not slot["recovery_required"] and
                         not slot["terminal_event_confirmed"]) and
                    ordinary_pending is not None and
                    ordinary_pending == snapshot, "EXPECTATION",
                    f"{step_label} cannot emit the latest ordinary status")
            ordinary_pending = None
            pending_indication = "ordinary_status"
        elif action == "confirm_ordinary_status":
            _mapping(raw_step, {"action"}, set(), step_label)
            require(pending_indication == "ordinary_status", "EXPECTATION",
                    f"{step_label} has no ordinary status to confirm")
            pending_indication = None
            features.add("ordinary_status_confirmation")
        elif action == "emit_status":
            _mapping(raw_step, {"action"}, set(), step_label)
            require(connected and slot is not None and
                    slot["phase"] != record_rules["active_phase"] and
                    slot["accepted_confirmed"] and slot["status_changed"] and
                    not slot["status_confirmed"] and
                    not slot["recovery_required"] and
                    ordinary_pending is None and
                    pending_indication is None, "EXPECTATION",
                    f"{step_label} cannot emit the final status")
            pending_indication = "final_status"
        elif action == "confirm_status":
            _mapping(raw_step, {"action"}, set(), step_label)
            require(slot is not None and pending_indication == "final_status",
                    "EXPECTATION", f"{step_label} has no final status to confirm")
            slot["status_confirmed"] = True
            pending_indication = None
            features.add("status_confirmation")
        elif action == "emit_terminal":
            step = _mapping(raw_step, {
                "action", "operation_id", "operation", "event",
            }, set(), step_label)
            operation_id = _integer(step["operation_id"],
                                    f"{step_label}.operation_id", 1, UINT32_MAX)
            operation = _string(step["operation"], f"{step_label}.operation")
            event = _string(step["event"], f"{step_label}.event")
            require(connected and slot is not None and
                    slot["phase"] != record_rules["active_phase"] and
                    slot["accepted_confirmed"] and
                    (not slot["status_changed"] or slot["status_confirmed"]) and
                    pending_indication is None and
                    not slot["terminal_event_emitted"] and
                    not slot["recovery_required"] and
                    operation_id == slot["operation_id"] and
                    operation == slot["operation"] and
                    event == rules["sequencing"]["terminal_events"][operation],
                    "EXPECTATION", f"{step_label} terminal event is inconsistent")
            if ordinary_pending is not None:
                features.add("ordinary_status_deferred")
            slot["terminal_event_emitted"] = True
            pending_indication = "terminal_event"
            features.add("operation_correlation")
            features.add(f"terminal_event:{operation}")
        elif action == "confirm_terminal":
            _mapping(raw_step, {"action"}, set(), step_label)
            require(slot is not None and pending_indication == "terminal_event",
                    "EXPECTATION", f"{step_label} has no terminal event to confirm")
            slot["terminal_event_confirmed"] = True
            pending_indication = None
            features.add("terminal_confirmation")
        elif action == "query":
            step = _mapping(raw_step, {"action", "expect"},
                            {"operation_id", "operation", "failure"}, step_label)
            require(connected, "EXPECTATION",
                    f"{step_label} cannot query while disconnected")
            require(pending_indication is None, "EXPECTATION",
                    f"{step_label} is blocked by an outstanding indication")
            expected = _string(step["expect"], f"{step_label}.expect")
            actual = (lifecycle["get_operation_no_record_status"]
                      if slot is None else slot["phase"])
            require(actual == expected, "EXPECTATION",
                    f"{step_label} expected {expected}, got {actual}")
            if slot is not None:
                require(set(step) == {
                    "action", "expect", "operation_id", "operation", "failure",
                }, "MISSING_FIELD", f"{step_label} must assert the exact record")
                require(step["operation_id"] == slot["operation_id"] and
                        step["operation"] == slot["operation"] and
                        step["failure"] == slot["failure"], "EXPECTATION",
                        f"{step_label} operation record differs")
            if (reconnected and slot is not None and
                    slot["phase"] != record_rules["active_phase"] and
                    slot["recovery_required"]):
                recovered_terminal = True
                features.add("disconnect_recovery")
                features.add(f"disconnect_recovery:{slot['operation']}")
            if actual == lifecycle["get_operation_no_record_status"] and \
                    reboot_cleared_record:
                features.add("reboot_clears")
            if actual == lifecycle["get_operation_no_record_status"] and \
                    ids_exhausted:
                features.add("id_exhaustion_no_record")
        elif action == "status_query":
            step = _mapping(raw_step, {"action", "expect"}, set(), step_label)
            require(connected and pending_indication is None and
                    _string(step["expect"], f"{step_label}.expect") == "CURRENT",
                    "EXPECTATION", f"{step_label} status query is invalid")
            if slot is not None and slot["phase"] == record_rules["active_phase"]:
                features.add("status_query_while_active")
            if recovered_terminal:
                features.add("status_recovery")
        elif action == "ack":
            step = _mapping(raw_step, {"action", "operation_id", "expect"},
                            set(), step_label)
            require(connected, "EXPECTATION",
                    f"{step_label} cannot ACK while disconnected")
            operation_id = _integer(step["operation_id"],
                                    f"{step_label}.operation_id", 1, UINT32_MAX)
            expected = _string(step["expect"], f"{step_label}.expect")
            if pending_indication is not None:
                actual = "ATT:profile_tx_indication_pending"
                reason = "pending_indication"
            elif slot is None or slot["operation_id"] != operation_id:
                actual = lifecycle["ack_missing_or_mismatch_status"]
                reason = "missing_or_mismatch"
            elif slot["phase"] == record_rules["active_phase"]:
                actual = lifecycle["ack_active_status"]
                reason = "active"
            elif ((not slot["recovery_required"] and
                   slot["terminal_event_confirmed"]) or
                  (recovered_terminal and
                   lifecycle["reconnect_ack_without_replay"])):
                actual = ok_status
                reason = "accepted"
            else:
                actual = lifecycle["ack_before_terminal_event_status"]
                reason = "terminal_unconfirmed"
            require(actual == expected, "EXPECTATION",
                    f"{step_label} expected {expected}, got {actual}")
            if reason == "active":
                features.add("active_ack_busy")
            elif reason == "terminal_unconfirmed":
                features.add("terminal_ack_busy")
            elif reason == "missing_or_mismatch":
                features.add("mismatched_ack_not_found")
            elif reason == "pending_indication":
                features.add("unconfirmed_event_blocks_ack")
            elif reason == "accepted":
                pending_indication = "ack_response"
        elif action == "confirm_ack":
            _mapping(raw_step, {"action"}, set(), step_label)
            require(slot is not None and pending_indication == "ack_response",
                    "EXPECTATION", f"{step_label} has no ACK response to confirm")
            acknowledged_operation = slot["operation"]
            slot = None
            pending_indication = None
            recovered_terminal = False
            features.add("terminal_ack")
            features.add("ack_confirmation_clears")
            features.add(f"terminal_ack:{acknowledged_operation}")
        elif action == "disconnect":
            _mapping(raw_step, {"action"}, set(), step_label)
            require(connected, "EXPECTATION",
                    f"{step_label} is already disconnected")
            if (slot is not None and
                    (slot["phase"] != record_rules["active_phase"] or
                     pending_indication in {
                         "accepted_response", "final_status", "terminal_event"
                     })):
                slot["recovery_required"] = True
            if pending_indication == "accepted_response":
                features.add("accepted_response_discarded")
            if pending_indication == "ack_response":
                features.add("ack_disconnect_retains")
            if ordinary_pending is not None or pending_indication == "ordinary_status":
                features.add("ordinary_status_discarded")
            if pending_indication == "final_status":
                features.add("final_status_discarded")
            ordinary_pending = None
            pending_indication = None
            connected = False
            recovered_terminal = False
        elif action == "reconnect":
            _mapping(raw_step, {"action"}, set(), step_label)
            require(not connected, "EXPECTATION",
                    f"{step_label} is already connected")
            connected = True
            reconnected = True
        elif action == "expect_no_replay":
            _mapping(raw_step, {"action"}, set(), step_label)
            require(connected and reconnected and slot is not None and
                    slot["phase"] != record_rules["active_phase"] and
                    slot["recovery_required"] and
                    pending_indication is None, "EXPECTATION",
                    f"{step_label} expected no replayed terminal event")
            features.add("no_terminal_replay")
        elif action == "exhaust_ids":
            step = _mapping(raw_step, {"action", "expect"}, set(), step_label)
            require(connected and slot is None and
                    pending_indication is None and UINT32_MAX in seen_ids and
                    _string(step["expect"], f"{step_label}.expect") ==
                    lifecycle["operation_id_exhausted_status"], "EXPECTATION",
                    f"{step_label} ID exhaustion result is invalid")
            ids_exhausted = True
            features.add("id_exhaustion")
        elif action == "reboot":
            _mapping(raw_step, {"action"}, set(), step_label)
            reboot_cleared_record = slot is not None
            slot = None
            pending_indication = None
            seen_ids.clear()
            ids_exhausted = False
            connected = False
            reconnected = False
            recovered_terminal = False
            ordinary_pending = None
            features.add("reboot")
        else:
            fail("VALUE", f"unknown operation action: {action}")
    if lifecycle["must_reach_terminal"]:
        require(slot is None or slot["phase"] != record_rules["active_phase"],
                "OPERATION", f"{label} leaves an accepted operation active")
    require(pending_indication is None, "OPERATION",
            f"{label} leaves an indication unconfirmed")
    return features


def validate_vectors(protocol: dict[str, Any],
                     vectors: dict[str, Any] | None = None) -> None:
    if vectors is None:
        vectors = load_vectors()
    root = _mapping(vectors, {
        "format_version", "profile", "messages", "transport_cases",
        "routing_cases", "result_matrix_cases", "wifi_cases",
        "operation_cases",
    }, set(), "vectors")
    require(_integer(root["format_version"], "vectors.format_version") == 4,
            "VALUE", "vector format version must be 4")
    require(root["profile"] == protocol["profile"]["name"], "VERSION",
            "vector profile differs from protocol")
    messages = _mapping(root["messages"], {"valid", "invalid"}, set(),
                        "vectors.messages")
    valid = _list(messages["valid"], "vectors.messages.valid", True)
    invalid = _list(messages["invalid"], "vectors.messages.invalid", True)
    ids: set[str] = set()
    request_coverage: set[str] = set()
    response_coverage: set[str] = set()
    event_coverage: set[str] = set()
    application_error_coverage: set[str] = set()
    operation_record_coverage: set[str] = set()
    for raw_case in valid:
        case = _message_shape(raw_case)
        case_id = _string(case["id"], "message.id")
        require(case_id not in ids, "DUPLICATE_ID",
                f"duplicate vector ID: {case_id}")
        ids.add(case_id)
        decoded = validate_message(protocol, case)
        if case["kind"] == "request":
            request_coverage.add(case["name"])
        elif case["kind"] == "response":
            command = _command_maps(protocol)[1][case["name"]]
            success = (protocol["wire_rules"]["response"]
                       ["asynchronous_success_status"] if command["asynchronous"]
                       else protocol["wire_rules"]["response"]
                       ["synchronous_success_status"])
            if case["status"] == success:
                response_coverage.add(case["name"])
                if command.get("response_semantic") == "operation_record":
                    record = protocol["wire_rules"]["operation_record"]
                    scan_operation = protocol["wire_rules"]["scan_result"][
                        "scan_operation"
                    ]
                    phase = decoded["phase"]
                    operation = decoded["operation"]
                    count = decoded["count"]
                    if phase == record["active_phase"]:
                        operation_record_coverage.add("active")
                    elif operation == scan_operation:
                        if phase == record["succeeded_phase"] and count > 0:
                            operation_record_coverage.add(
                                "scan_succeeded_with_results"
                            )
                        elif phase == record["failed_phase"] and count == 0:
                            operation_record_coverage.add("scan_failed_empty")
                    elif phase == record["succeeded_phase"] and count == 0:
                        operation_record_coverage.add("non_scan_succeeded_empty")
                    elif phase == record["failed_phase"] and count == 0:
                        operation_record_coverage.add("non_scan_failed_empty")
        elif case["kind"] == "event":
            event_coverage.add(case["name"])
        else:
            error_kind = ("reserved" if case["offending_opcode"] in
                          protocol["protocol"]["transport"]
                          ["reserved_request_opcodes"] else "unknown")
            application_error_coverage.add(error_kind)
    for raw_case in invalid:
        case = _mapping(raw_case,
                        set(_message_shape({key: value for key, value in raw_case.items()
                                            if key != "expected_error"})),
                        {"expected_error"}, "invalid message")
        expected = _string(case["expected_error"],
                           f"{case.get('id', '?')}.expected_error")
        normal = dict(case)
        del normal["expected_error"]
        case_id = _string(normal["id"], "message.id")
        require(case_id not in ids, "DUPLICATE_ID",
                f"duplicate vector ID: {case_id}")
        ids.add(case_id)
        try:
            validate_message(protocol, normal)
        except ContractError as exc:
            require(exc.code == expected, "EXPECTATION",
                    f"{case_id} expected {expected}, got {exc.code}")
        else:
            fail("EXPECTATION", f"negative vector passed: {case_id}")
    command_names = {item["name"] for item in protocol["commands"]}
    event_names = {item["name"] for item in protocol["events"]}
    require(request_coverage == command_names, "COVERAGE",
            "valid request vectors must cover every command")
    require(response_coverage == command_names, "COVERAGE",
            "valid success responses must cover every command")
    require(event_coverage == event_names, "COVERAGE",
            "valid vectors must cover every event")
    require(application_error_coverage == {"unknown", "reserved"}, "COVERAGE",
            "valid vectors must cover unknown and reserved opcode envelopes")
    require(operation_record_coverage == {
        "active", "scan_succeeded_with_results", "scan_failed_empty",
        "non_scan_succeeded_empty", "non_scan_failed_empty",
    }, "COVERAGE", "valid vectors must cover operation record phase/count forms")

    maximum = protocol["protocol"]["transport"]["maximum_att_value_bytes"]
    boundary_valid = False
    boundary_invalid = False
    for index, raw_case in enumerate(_list(root["transport_cases"],
                                           "vectors.transport_cases", True)):
        case = _mapping(raw_case, {"id", "length", "valid"}, set(),
                        f"transport_cases[{index}]")
        case_id = _string(case["id"], f"transport_cases[{index}].id")
        require(case_id not in ids, "DUPLICATE_ID",
                f"duplicate vector ID: {case_id}")
        ids.add(case_id)
        length = _integer(case["length"], f"{case_id}.length", 0)
        expected_valid = _boolean(case["valid"], f"{case_id}.valid")
        try:
            validate_att_value_length(protocol, length)
        except ContractError:
            actual_valid = False
        else:
            actual_valid = True
        require(actual_valid == expected_valid, "EXPECTATION",
                f"{case_id} ATT boundary expectation differs")
        boundary_valid |= length == maximum and expected_valid
        boundary_invalid |= length == maximum + 1 and not expected_valid
    require(boundary_valid and boundary_invalid, "COVERAGE",
            "transport vectors must cover maximum and maximum+1")

    routing_features: set[str] = set()
    low_mtu_command_coverage: set[str] = set()
    low_mtu_exception_coverage: set[str] = set()
    full_mtu_admitted = False
    routing_cases = _list(root["routing_cases"],
                          "vectors.routing_cases", True)
    commands_by_id = _command_maps(protocol)[0]
    transport = protocol["protocol"]["transport"]
    for raw_case in routing_cases:
        case_id = _string(raw_case.get("id") if type(raw_case) is dict else None,
                          "routing_case.id")
        require(case_id not in ids, "DUPLICATE_ID",
                f"duplicate vector ID: {case_id}")
        ids.add(case_id)
        routing_features.add(_validate_routing_case(protocol, raw_case))
        command = commands_by_id.get(raw_case["opcode"])
        if command is not None:
            if raw_case["att_mtu"] < transport["required_att_mtu"]:
                if (command["requires_full_mtu"] and raw_case["expect"] ==
                        f"APP:{transport['low_mtu']['other_commands_status']}"):
                    low_mtu_command_coverage.add(command["name"])
                elif (not command["requires_full_mtu"] and
                      raw_case["expect"] == "ADMITTED"):
                    low_mtu_exception_coverage.add(command["name"])
            elif raw_case["expect"] == "ADMITTED":
                full_mtu_admitted = True
    required_routing = {
        *protocol["protocol"]["att_errors"]["gatt_precedence"],
        *protocol["protocol"]["att_errors"]["application_precedence"],
        "admitted",
    }
    require(required_routing <= routing_features, "COVERAGE",
            "routing scenarios do not cover protocol precedence")
    lifecycle = protocol["wire_rules"]["operation_lifecycle"]
    recovery_commands = {
        lifecycle["reconnect_query"], lifecycle["reconnect_status_query"],
        *transport["operation_slot_controls"],
    }
    low_mtu_exceptions = {item["name"] for item in protocol["commands"]
                          if not item["requires_full_mtu"]}
    require(recovery_commands <= low_mtu_command_coverage and
            low_mtu_exception_coverage == low_mtu_exceptions and
            full_mtu_admitted,
            "COVERAGE", "routing scenarios do not cover MTU recovery paths")

    result_operations: set[str] = set()
    failure_matrix = protocol["wire_rules"]["operation_result"]["failure_matrix"]
    for index, raw_case in enumerate(_list(
            root["result_matrix_cases"], "vectors.result_matrix_cases", True)):
        case = _mapping(raw_case, {"id", "operation", "allowed_failures"},
                        set(), f"result_matrix_cases[{index}]")
        case_id = _string(case["id"], f"result_matrix_cases[{index}].id")
        require(case_id not in ids, "DUPLICATE_ID",
                f"duplicate vector ID: {case_id}")
        ids.add(case_id)
        operation = _string(case["operation"], f"{case_id}.operation")
        require(operation in failure_matrix and operation not in result_operations,
                "OPERATION", f"{case_id} operation is unknown or duplicated")
        failures = _string_list(case["allowed_failures"],
                                f"{case_id}.allowed_failures", True)
        require(failures == failure_matrix[operation], "EXPECTATION",
                f"{case_id} failure matrix differs from the protocol")
        result_operations.add(operation)
    require(result_operations == set(failure_matrix), "COVERAGE",
            "result matrix vectors must cover every operation")

    result_rules = protocol["wire_rules"]["operation_result"]
    wifi_expectations = {
        **{f"success.{name}": value for name, value in
           result_rules["success_postconditions"].items()},
        **{f"edge.{name}": value for name, value in
           result_rules["edge_cases"].items()},
    }
    scan_policy = protocol["wire_rules"]["scan_result"]
    scan_security = scan_policy["representable_security"]
    representable_authmodes = {
        authmode for values in scan_security.values() for authmode in values
    }
    scan_filter_cases: set[str] = set()
    wifi_cases: set[str] = set()
    for index, raw_case in enumerate(_list(root["wifi_cases"],
                                           "vectors.wifi_cases", True)):
        case = _mapping(raw_case, {"id", "case", "expect"}, set(),
                        f"wifi_cases[{index}]")
        case_id = _string(case["id"], f"wifi_cases[{index}].id")
        require(case_id not in ids, "DUPLICATE_ID",
                f"duplicate vector ID: {case_id}")
        ids.add(case_id)
        case_name = _string(case["case"], f"{case_id}.case")
        if case_name in wifi_expectations:
            require(case_name not in wifi_cases, "OPERATION",
                    f"{case_id} Wi-Fi case is duplicated")
            require(case["expect"] == wifi_expectations[case_name],
                    "EXPECTATION",
                    f"{case_id} Wi-Fi edge result differs from the protocol")
            wifi_cases.add(case_name)
            continue
        require(case_name in {"scan_filtering", "scan_filtering_under_limit"} and
                case_name not in scan_filter_cases,
                "OPERATION", f"{case_id} Wi-Fi case is unknown or duplicated")
        expected = _mapping(case["expect"], {
            "input", "filtered_ssids", "count",
        }, set(), f"{case_id}.expect")
        input_records = _list(expected["input"], f"{case_id}.input", True)
        filtered_ssids = _list(expected["filtered_ssids"],
                               f"{case_id}.filtered_ssids")
        for index, raw_record in enumerate(input_records):
            record = _mapping(raw_record, {"ssid", "authmode"}, set(),
                              f"{case_id}.input[{index}]")
            require(type(record["ssid"]) is str,
                    "TYPE", f"{case_id}.input[{index}].ssid must be a string")
            _string(record["authmode"], f"{case_id}.input[{index}].authmode")
        expected_filtered = [
            record["ssid"] for record in input_records
            if record["ssid"] and record["authmode"] in representable_authmodes
        ]
        filtered_values = [
            _string(value, f"{case_id}.filtered_ssids[{index}]")
            for index, value in enumerate(filtered_ssids)
        ]
        require(len(filtered_values) == len(set(filtered_values)),
                "DUPLICATE_ID", f"{case_id}.filtered_ssids contains duplicates")
        expected_count = min(len(expected_filtered),
                             scan_policy["maximum_records"])
        actual_count = _integer(expected["count"], f"{case_id}.count", 0,
                                scan_policy["maximum_records"])
        require(actual_count == len(filtered_values) == expected_count,
                "EXPECTATION", f"{case_id} filtered count differs")
        expected_set = set(expected_filtered)
        actual_set = set(filtered_values)
        require(actual_set <= expected_set and
                (len(expected_filtered) > scan_policy["maximum_records"] or
                 actual_set == expected_set), "EXPECTATION",
                f"{case_id} filtered records differ")
        scan_filter_cases.add(case_name)
    require(wifi_cases == set(wifi_expectations) and
            scan_filter_cases == {"scan_filtering", "scan_filtering_under_limit"},
            "COVERAGE", "Wi-Fi vectors must cover policy and edge cases")

    operation_features: set[str] = set()
    for raw_case in _list(root["operation_cases"],
                          "vectors.operation_cases", True):
        case_id = _string(raw_case.get("id") if type(raw_case) is dict else None,
                          "operation_case.id")
        require(case_id not in ids, "DUPLICATE_ID",
                f"duplicate vector ID: {case_id}")
        ids.add(case_id)
        operation_features |= _validate_operation_case(protocol, raw_case)
    required_features = {
        "accepted_confirmation", "status_confirmation",
        "terminal_confirmation", "operation_correlation",
        "disconnect_recovery", "status_recovery", "no_terminal_replay",
        "active_ack_busy", "terminal_ack_busy", "mismatched_ack_not_found",
        "unconfirmed_event_blocks_ack", "active_blocks_new",
        "terminal_blocks_new", "status_query_while_active",
        "ack_confirmation_clears", "ack_disconnect_retains",
        "terminal_ack", "reboot_clears", "id_exhaustion",
        "id_exhaustion_empty", "id_exhaustion_no_record",
        "status_coalesced", "status_latest_replaced",
        "ordinary_status_confirmation", "ordinary_status_discarded",
        "ordinary_status_deferred", "accepted_response_discarded",
        "final_status_latched", "final_status_discarded",
        "connect_authentication_failure",
        *{f"timeout:{operation}" for operation in
          protocol["wire_rules"]["operation_lifecycle"]["accepted_commands"]},
        *{f"failed:{operation}" for operation in
          protocol["wire_rules"]["operation_lifecycle"]["accepted_commands"]},
        *{f"disconnect_recovery:{operation}" for operation in
          protocol["wire_rules"]["operation_lifecycle"]["accepted_commands"]},
        *{f"terminal_ack:{operation}" for operation in
          protocol["wire_rules"]["operation_lifecycle"]["accepted_commands"]},
        *{f"succeeded:{operation}" for operation in
          protocol["wire_rules"]["operation_lifecycle"]["accepted_commands"]},
        *{f"terminal_event:{operation}" for operation in
          protocol["wire_rules"]["operation_lifecycle"]["accepted_commands"]},
    }
    require(required_features <= operation_features, "COVERAGE",
            "operation scenarios do not cover the recovery contract")


def normalized_digest(protocol: dict[str, Any],
                      vectors: dict[str, Any] | None = None) -> str:
    if vectors is None:
        vectors = load_vectors()
    encoded = json.dumps(
        {"protocol": protocol, "vectors": vectors},
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate Device Link contract")
    parser.add_argument("--print-digest", action="store_true")
    parser.add_argument("--protocol", type=Path, default=PROTOCOL_PATH)
    parser.add_argument("--vectors", type=Path, default=VECTORS_PATH)
    args = parser.parse_args(argv)
    try:
        protocol = load_protocol(args.protocol)
        vectors = load_vectors(args.vectors)
        validate_protocol(protocol)
        validate_version(protocol, args.protocol.parent / "VERSION")
        validate_vectors(protocol, vectors)
        digest = normalized_digest(protocol, vectors)
    except ContractError as exc:
        print(exc, file=sys.stderr)
        return 1
    if args.print_digest:
        print(digest)
    else:
        print(f"schema_digest={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
