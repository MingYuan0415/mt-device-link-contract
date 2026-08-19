from __future__ import annotations

import copy
import json
import tempfile
import unittest
import uuid
from pathlib import Path

import yaml

from tooling.check import (ContractError, load_protocol, load_vectors,
                           normalized_digest, validate_att_value_length,
                           validate_message, validate_protocol,
                           validate_vectors, validate_version)


ROOT = Path(__file__).resolve().parents[1]


def contract_error_code(function, *args) -> str:
    try:
        function(*args)
    except ContractError as exc:
        return exc.code
    raise AssertionError("expected ContractError")


class ProtocolSourceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.protocol = load_protocol()
        self.vectors = load_vectors()

    def test_protocol_vectors_and_version_are_valid(self) -> None:
        validate_protocol(self.protocol)
        validate_version(self.protocol)
        validate_vectors(self.protocol, self.vectors)

    def test_duplicate_yaml_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.yaml"
            path.write_text(
                "schema_version: 1\nschema_version: 2\n",
                encoding="utf-8",
            )
            self.assertEqual(contract_error_code(load_protocol, path),
                             "DUPLICATE_KEY")

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text(
                '{"format_version": 2, "format_version": 3}',
                encoding="utf-8",
            )
            self.assertEqual(contract_error_code(load_vectors, path),
                             "DUPLICATE_KEY")

    def test_non_standard_json_constants_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nan.json"
            path.write_text('{"format_version": NaN}', encoding="utf-8")
            self.assertEqual(contract_error_code(load_vectors, path), "LOAD")

    def test_unknown_and_missing_fields_are_distinct(self) -> None:
        missing = copy.deepcopy(self.protocol)
        del missing["profile"]["name"]
        self.assertEqual(contract_error_code(validate_protocol, missing),
                         "MISSING_FIELD")

        unknown = copy.deepcopy(self.protocol)
        unknown["profile"]["legacy"] = True
        self.assertEqual(contract_error_code(validate_protocol, unknown),
                         "UNKNOWN_FIELD")

    def test_malformed_shapes_raise_contract_errors(self) -> None:
        bad_status = copy.deepcopy(self.protocol)
        bad_status["commands"][0]["allowed_statuses"][0] = {}
        bad_enum = copy.deepcopy(self.protocol)
        bad_enum["types"]["scan_network"]["fields"][1]["enum"] = {}
        mutations = [
            [],
            {"schema_version": 1},
            {**self.protocol, "commands": [None]},
            bad_status,
            bad_enum,
        ]
        for mutation in mutations:
            with self.subTest(mutation=type(mutation).__name__):
                code = contract_error_code(validate_protocol, mutation)
                self.assertIn(code, {
                    "TYPE", "MISSING_FIELD", "UNKNOWN_FIELD",
                })

        malformed_message = {
            "id": "malformed",
            "kind": [],
            "status": None,
            "hex": "",
        }
        self.assertEqual(
            contract_error_code(validate_message, self.protocol,
                                malformed_message),
            "TYPE",
        )

    def test_version_file_is_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "VERSION"
            path.write_text("1.0.0", encoding="ascii")
            self.assertEqual(
                contract_error_code(validate_version, self.protocol, path),
                "VERSION",
            )

    def test_uuid_att_octets_are_full_little_endian(self) -> None:
        gatt = self.protocol["protocol"]["gatt"]
        definitions = [
            gatt["service"],
            gatt["characteristics"]["command_rx"],
            gatt["characteristics"]["server_tx"],
        ]
        for definition in definitions:
            with self.subTest(uuid=definition["uuid"]):
                expected = uuid.UUID(definition["uuid"]).bytes[::-1].hex()
                self.assertEqual(definition["att_octets"], expected)

    def test_gatt_procedures_and_att_errors_are_fixed(self) -> None:
        gatt = self.protocol["protocol"]["gatt"]
        command_rx = gatt["characteristics"]["command_rx"]
        server_tx = gatt["characteristics"]["server_tx"]
        self.assertEqual(command_rx["write_procedure"], "request")
        self.assertEqual(server_tx["cccd_uuid"], 0x2902)
        self.assertIs(server_tx["cccd_write_encrypted"], True)
        self.assertEqual(server_tx["indication_enable_value_le"], "0200")
        errors = self.protocol["protocol"]["att_errors"]
        self.assertEqual({
            name: errors[name] for name in (
                "insufficient_encryption",
                "invalid_attribute_value_length",
                "value_not_allowed",
                "cccd_improperly_configured",
                "procedure_already_in_progress",
            )
        }, {
            "insufficient_encryption": 0x0f,
            "invalid_attribute_value_length": 0x0d,
            "value_not_allowed": 0x13,
            "cccd_improperly_configured": 0xfd,
            "procedure_already_in_progress": 0xfe,
        })

    def test_transport_math_and_boundaries(self) -> None:
        transport = self.protocol["protocol"]["transport"]
        self.assertEqual(transport["att_pdu_bytes"], 498)
        self.assertEqual(transport["l2cap_sdu_bytes"], 498)
        self.assertEqual(transport["l2cap_pdu_bytes"], 502)
        self.assertEqual(
            transport["l2cap_pdu_bytes"],
            transport["link_layer_payload_bytes"] *
            transport["link_layer_payloads_for_full_l2cap_pdu"],
        )
        validate_att_value_length(self.protocol, 495)
        self.assertEqual(
            contract_error_code(validate_att_value_length,
                                self.protocol, 496),
            "ATT_VALUE_TOO_LONG",
        )

    def test_get_info_fits_default_att_mtu(self) -> None:
        case = next(
            item for item in self.vectors["messages"]["valid"]
            if item["id"] == "get-info-response"
        )
        encoded = bytes.fromhex(case["hex"])
        self.assertEqual(len(encoded), 11)
        self.assertLessEqual(
            len(encoded),
            self.protocol["protocol"]["transport"]["minimum_att_mtu"] - 3,
        )

    def test_maximum_scan_event_is_180_bytes(self) -> None:
        case = next(
            item for item in self.vectors["messages"]["valid"]
            if item["id"] == "scan-complete-max"
        )
        self.assertEqual(len(bytes.fromhex(case["hex"])), 180)

    def test_digest_is_format_independent_and_semantic(self) -> None:
        digest = normalized_digest(self.protocol, self.vectors)
        protocol_crlf = yaml.safe_load(
            (ROOT / "protocol.yaml").read_text(encoding="utf-8")
            .replace("\n", "\r\n")
        )
        vectors_reordered = json.loads(
            json.dumps(self.vectors, sort_keys=True)
        )
        self.assertEqual(
            digest,
            normalized_digest(protocol_crlf, vectors_reordered),
        )

        mutated = copy.deepcopy(self.vectors)
        mutated["messages"]["valid"][0]["request_id"] = 99
        self.assertNotEqual(digest, normalized_digest(self.protocol, mutated))


class MessageVectorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.protocol = load_protocol()
        self.vectors = load_vectors()

    def test_every_valid_message_decodes(self) -> None:
        for case in self.vectors["messages"]["valid"]:
            with self.subTest(case=case["id"]):
                validate_message(self.protocol, case)

    def test_vector_unknown_missing_and_wrong_type_are_rejected(self) -> None:
        missing = copy.deepcopy(self.vectors)
        del missing["messages"]["valid"][0]["hex"]
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, missing),
            "MISSING_FIELD",
        )

        unknown = copy.deepcopy(self.vectors)
        unknown["messages"]["valid"][0]["legacy"] = True
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, unknown),
            "UNKNOWN_FIELD",
        )

        wrong_type = copy.deepcopy(self.vectors)
        wrong_type["transaction_cases"][0]["steps"][0]["action"] = []
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, wrong_type),
            "TYPE",
        )

    def test_every_negative_message_matches_its_error_category(self) -> None:
        for case in self.vectors["messages"]["invalid"]:
            normal = dict(case)
            expected = normal.pop("expected_error")
            with self.subTest(case=case["id"]):
                self.assertEqual(
                    contract_error_code(
                        validate_message, self.protocol, normal
                    ),
                    expected,
                )

    def test_negative_intent_cannot_be_replaced_by_unrelated_failure(self) -> None:
        mutated = copy.deepcopy(self.vectors)
        for case in mutated["messages"]["invalid"]:
            case["hex"] = ""
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, mutated),
            "EXPECTATION",
        )

    def test_wrong_expected_error_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.vectors)
        mutated["messages"]["invalid"][0]["expected_error"] = "UTF8"
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, mutated),
            "EXPECTATION",
        )

    def test_status_matrix_coverage_is_enforced(self) -> None:
        mutated = copy.deepcopy(self.vectors)
        mutated["messages"]["valid"] = [
            case for case in mutated["messages"]["valid"]
            if case["id"] != "wifi-status-error-authentication"
        ]
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, mutated),
            "COVERAGE",
        )

    def test_operation_result_coverage_is_enforced(self) -> None:
        mutated = copy.deepcopy(self.vectors)
        mutated["messages"]["valid"] = [
            case for case in mutated["messages"]["valid"]
            if case["id"] != "operation-connect-authentication"
        ]
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, mutated),
            "COVERAGE",
        )

    def test_allowed_response_status_coverage_is_enforced(self) -> None:
        mutated = copy.deepcopy(self.vectors)
        mutated["messages"]["valid"] = [
            case for case in mutated["messages"]["valid"]
            if case["id"] != "connect-status-not-found"
        ]
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, mutated),
            "COVERAGE",
        )

    def test_transaction_scenario_coverage_is_enforced(self) -> None:
        mutated = copy.deepcopy(self.vectors)
        mutated["transaction_cases"] = [
            case for case in mutated["transaction_cases"]
            if case["id"] != "disconnect-no-replay"
        ]
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, mutated),
            "COVERAGE",
        )

    def test_operation_postcondition_coverage_is_enforced(self) -> None:
        mutated = copy.deepcopy(self.vectors)
        mutated["transaction_cases"] = [
            case for case in mutated["transaction_cases"]
            if case["id"] != "connect-success-postcondition"
        ]
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, mutated),
            "COVERAGE",
        )

    def test_transaction_expectations_are_checked(self) -> None:
        mutated = copy.deepcopy(self.vectors)
        case = next(
            item for item in mutated["transaction_cases"]
            if item["id"] == "get-info-at-mtu23"
        )
        case["steps"][0]["expect"] = "response:MTU_TOO_SMALL"
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, mutated),
            "EXPECTATION",
        )


class ProtocolMutationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.protocol = load_protocol()
        self.vectors = load_vectors()

    def assert_protocol_mutation_fails(self, mutation) -> None:
        candidate = copy.deepcopy(self.protocol)
        mutation(candidate)
        try:
            validate_protocol(candidate)
            validate_vectors(candidate, self.vectors)
        except ContractError as exc:
            code = exc.code
        else:
            self.fail("protocol mutation was accepted")
        self.assertIn(code, {
            "VALUE", "TRANSPORT_MATH", "UNKNOWN_FIELD", "MISSING_FIELD",
            "WIRE_TYPE", "ENUM", "STATUS", "UUID", "LENGTH", "COVERAGE",
            "EXPECTATION", "TYPE",
        })

    def test_transport_mutations_are_rejected(self) -> None:
        mutations = [
            lambda p: p["protocol"]["transport"].__setitem__(
                "required_att_mtu", 497
            ),
            lambda p: p["protocol"]["transport"].__setitem__(
                "l2cap_sdu_bytes", 502
            ),
            lambda p: p["protocol"]["transport"].__setitem__(
                "maximum_att_value_bytes", 496
            ),
            lambda p: p["protocol"]["gatt"]["characteristics"][
                "command_rx"
            ].__setitem__("max_value_bytes", 495.0),
            lambda p: p["protocol"]["gatt"]["characteristics"][
                "server_tx"
            ].__setitem__("properties", ["notify"]),
            lambda p: p["protocol"]["gatt"]["characteristics"][
                "command_rx"
            ].__setitem__("write_procedure", "command"),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_protocol_mutation_fails(mutation)

    def test_layout_and_status_mutations_are_rejected(self) -> None:
        mutations = [
            lambda p: p["commands"][0]["response"].append({
                "name": "legacy", "wire": "u8",
            }),
            lambda p: p["commands"][3]["request"][0].__setitem__(
                "max_bytes", 31
            ),
            lambda p: p["types"]["scan_network"]["fields"][2].__setitem__(
                "max", 1
            ),
            lambda p: p["commands"][4]["allowed_statuses"].append("STORAGE"),
            lambda p: p["events"][2].__setitem__("id", 4),
            lambda p: p["wire_types"]["i8"].__setitem__(
                "encoding", "sign_magnitude"
            ),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_protocol_mutation_fails(mutation)

    def test_state_and_operation_matrix_mutations_are_rejected(self) -> None:
        mutations = [
            lambda p: p["wire_rules"]["wifi_status"]["state_matrix"][
                "CONNECTED"
            ].append("LINK_LOST"),
            lambda p: p["wire_rules"]["operation_completion"][
                "failure_matrix"
            ]["SET_CREDENTIALS"].append("AUTHENTICATION"),
            lambda p: p["wire_rules"]["sequencing"].__setitem__(
                "ble_disconnect_completion_replay", True
            ),
            lambda p: p["wire_rules"]["operation_completion"][
                "success_postconditions"
            ].__setitem__("FORGET", "profile_absent"),
            lambda p: p["wire_rules"]["admission"][
                "service_unavailable_bypass"
            ].append("SET_CREDENTIALS"),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_protocol_mutation_fails(mutation)


if __name__ == "__main__":
    unittest.main()
