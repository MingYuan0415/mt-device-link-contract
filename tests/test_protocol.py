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

    def test_duplicate_yaml_and_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            yaml_path = Path(directory) / "duplicate.yaml"
            yaml_path.write_text(
                "schema_version: 1\nschema_version: 2\n", encoding="utf-8"
            )
            self.assertEqual(contract_error_code(load_protocol, yaml_path),
                             "DUPLICATE_KEY")

            json_path = Path(directory) / "duplicate.json"
            json_path.write_text(
                '{"format_version": 3, "format_version": 4}',
                encoding="utf-8",
            )
            self.assertEqual(contract_error_code(load_vectors, json_path),
                             "DUPLICATE_KEY")

    def test_non_standard_json_constants_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nan.json"
            path.write_text('{"format_version": NaN}', encoding="utf-8")
            self.assertEqual(contract_error_code(load_vectors, path), "LOAD")

    def test_version_file_requires_one_newline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "VERSION"
            path.write_text("1.0.0", encoding="ascii")
            self.assertEqual(
                contract_error_code(validate_version, self.protocol, path),
                "VERSION",
            )

    def test_uuid_octets_are_full_little_endian(self) -> None:
        gatt = self.protocol["protocol"]["gatt"]
        definitions = [gatt["service"], *gatt["characteristics"].values()]
        for definition in definitions:
            with self.subTest(uuid=definition["uuid"]):
                expected = uuid.UUID(definition["uuid"]).bytes[::-1].hex()
                self.assertEqual(definition["att_octets"], expected)

    def test_duplicate_gatt_uuid_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.protocol)
        service = candidate["protocol"]["gatt"]["service"]
        command = candidate["protocol"]["gatt"]["characteristics"]["command_rx"]
        command["uuid"] = service["uuid"]
        command["att_octets"] = service["att_octets"]
        self.assertEqual(
            contract_error_code(validate_protocol, candidate), "DUPLICATE_ID"
        )

        candidate = copy.deepcopy(self.protocol)
        candidate["commands"][1]["id"] = candidate["commands"][0]["id"]
        self.assertEqual(
            contract_error_code(validate_protocol, candidate), "DUPLICATE_ID"
        )

        candidate = copy.deepcopy(self.protocol)
        status_names = list(candidate["status_codes"])
        candidate["status_codes"][status_names[1]] = (
            candidate["status_codes"][status_names[0]]
        )
        self.assertEqual(
            contract_error_code(validate_protocol, candidate), "DUPLICATE_ID"
        )

    def test_checker_does_not_copy_profile_identity_or_uuid(self) -> None:
        checker = (ROOT / "tooling/check.py").read_text(encoding="utf-8")
        self.assertNotIn(self.protocol["profile"]["name"], checker)
        self.assertNotIn(
            self.protocol["protocol"]["gatt"]["service"]["uuid"], checker
        )
        registry_names = {
            *(item["name"] for item in self.protocol["commands"]),
            *(item["name"] for item in self.protocol["events"]),
            *self.protocol["status_codes"],
            *(name for values in self.protocol["enums"].values()
              for name in values),
        }
        semantic_enum_names = set(
            self.protocol["wire_rules"]["scan_result"]["representable_security"]
        )
        for name in registry_names:
            with self.subTest(registry=name):
                if name in semantic_enum_names:
                    continue
                self.assertNotIn(f'"{name}"', checker)
                self.assertNotIn(f"'{name}'", checker)

        def vector_ids(value):
            if isinstance(value, dict):
                if isinstance(value.get("id"), str):
                    yield value["id"]
                for child in value.values():
                    yield from vector_ids(child)
            elif isinstance(value, list):
                for child in value:
                    yield from vector_ids(child)

        for vector_id in vector_ids(self.vectors):
            with self.subTest(vector=vector_id):
                self.assertNotIn(vector_id, checker)

    def test_digest_is_format_independent_and_semantic(self) -> None:
        digest = normalized_digest(self.protocol, self.vectors)
        protocol_crlf = yaml.safe_load(
            (ROOT / "protocol.yaml").read_text(encoding="utf-8")
            .replace("\n", "\r\n")
        )
        reordered = json.loads(json.dumps(self.vectors, sort_keys=True))
        self.assertEqual(
            digest, normalized_digest(protocol_crlf, reordered)
        )
        mutated = copy.deepcopy(self.vectors)
        mutated["messages"]["valid"][0]["request_id"] = 99
        self.assertNotEqual(
            digest, normalized_digest(self.protocol, mutated)
        )

    def test_missing_command_field_is_a_contract_error(self) -> None:
        candidate = copy.deepcopy(self.protocol)
        del candidate["commands"][0]["asynchronous"]
        self.assertEqual(
            contract_error_code(validate_protocol, candidate),
            "MISSING_FIELD",
        )

        candidate = copy.deepcopy(self.protocol)
        del candidate["wire_rules"]["operation_lifecycle"][
            "accepted_response_field"
        ]
        self.assertEqual(
            contract_error_code(validate_protocol, candidate),
            "MISSING_FIELD",
        )


class SecurityAndTransportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.protocol = load_protocol()

    def assert_mutation_fails(self, mutation, expected: str) -> None:
        candidate = copy.deepcopy(self.protocol)
        mutation(candidate)
        self.assertEqual(contract_error_code(validate_protocol, candidate),
                         expected)

    def test_security_downgrades_are_rejected(self) -> None:
        mutations = [
            lambda p: p["protocol"]["security"].__setitem__("mitm", False),
            lambda p: p["protocol"]["security"].__setitem__("bonding", False),
            lambda p: p["protocol"]["security"].__setitem__("max_bonds", 2),
            lambda p: p["protocol"]["security"].__setitem__(
                "io_capability", "no_input_no_output"
            ),
            lambda p: p["protocol"]["security"].__setitem__(
                "association_model", "just_works"
            ),
            lambda p: p["protocol"]["security"].__setitem__(
                "encryption_key_bytes", 15
            ),
            lambda p: p["protocol"]["security"].__setitem__(
                "bond_replacement", "remote_transaction"
            ),
            lambda p: p["protocol"]["gatt"]["characteristics"][
                "command_rx"
            ].__setitem__("authenticated", False),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_mutation_fails(mutation, "SECURITY")

    def test_removed_bond_transaction_fields_are_rejected(self) -> None:
        removed = {
            "bond_replacement_commit": "after_all_requirements",
            "bond_replacement_commit_requires": [],
            "bond_replacement_candidate": "temporary",
            "bond_replacement_candidate_counts_toward_persistent_limit": False,
            "bond_replacement_failure_retains_old": True,
            "bond_replacement_precommit_power_loss_retains_old": True,
        }
        for key, value in removed.items():
            candidate = copy.deepcopy(self.protocol)
            candidate["protocol"]["security"][key] = value
            with self.subTest(key=key):
                self.assertEqual(
                    contract_error_code(validate_protocol, candidate),
                    "UNKNOWN_FIELD",
                )

        candidate = copy.deepcopy(self.protocol)
        candidate["protocol"]["transport"]["l2cap_pdu_bytes"] = 502
        self.assertEqual(contract_error_code(validate_protocol, candidate),
                         "UNKNOWN_FIELD")

        candidate = copy.deepcopy(self.protocol)
        candidate["protocol"]["att_errors"][
            "cccd_improperly_configured"
        ] = 0xfd
        self.assertEqual(contract_error_code(validate_protocol, candidate),
                         "UNKNOWN_FIELD")

        candidate = copy.deepcopy(self.protocol)
        candidate["protocol"]["att_errors"][
            "procedure_already_in_progress"
        ] = 0xfe
        self.assertEqual(contract_error_code(validate_protocol, candidate),
                         "UNKNOWN_FIELD")

    def test_mtu_math_and_att_boundaries(self) -> None:
        transport = self.protocol["protocol"]["transport"]
        self.assertEqual(transport["required_att_mtu"], 498)
        self.assertEqual(transport["maximum_att_value_bytes"], 495)
        self.assertNotIn("l2cap_pdu_bytes", transport)
        validate_att_value_length(self.protocol, 495)
        self.assertEqual(
            contract_error_code(validate_att_value_length,
                                self.protocol, 496),
            "ATT_VALUE_TOO_LONG",
        )

    def test_inconsistent_transport_math_is_rejected(self) -> None:
        mutations = [
            lambda p: p["protocol"]["transport"].__setitem__(
                "required_att_mtu", 497
            ),
            lambda p: p["protocol"]["transport"].__setitem__(
                "maximum_att_value_bytes", 496
            ),
            lambda p: p["protocol"]["limits"].__setitem__(
                "maximum_scan_event_bytes", 180
            ),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_mutation_fails(mutation, "TRANSPORT_MATH")

    def test_transport_identity_and_recovery_regressions_are_rejected(self) -> None:
        mutations = [
            (lambda p: p["protocol"]["transport"].__setitem__(
                "application_error_opcode", 0x81
            ), "OPERATION"),
            (lambda p: p["protocol"]["transport"][
                "reserved_request_opcodes"
            ].remove(0x70), "DUPLICATE_ID"),
            (lambda p: p["protocol"]["transport"].__setitem__(
                "operation_id_reuse_within_boot", True
            ), "OPERATION"),
            (lambda p: p["protocol"]["transport"]["low_mtu"].__setitem__(
                "recovery_requires_full_mtu", False
            ), "OPERATION"),
        ]
        for mutation, expected in mutations:
            with self.subTest(expected=expected):
                self.assert_mutation_fails(mutation, expected)

    def test_precedence_lists_are_complete_contract_errors(self) -> None:
        for key, expected in (("gatt_precedence", "SECURITY"),
                              ("application_precedence", "OPERATION")):
            candidate = copy.deepcopy(self.protocol)
            candidate["protocol"]["att_errors"][key].pop()
            with self.subTest(key=key):
                self.assertEqual(
                    contract_error_code(validate_protocol, candidate), expected
                )

    def test_nimble_security_gate_and_profile_att_values(self) -> None:
        errors = self.protocol["protocol"]["att_errors"]
        self.assertEqual(errors["security_gate_error"],
                         "insufficient_authentication")
        self.assertEqual(errors["profile_cccd_not_enabled"], 0xfd)
        self.assertEqual(errors["profile_tx_indication_pending"], 0xfe)
        self.assertEqual(errors["gatt_precedence"][0], "security_gate")

        candidate = copy.deepcopy(self.protocol)
        candidate["protocol"]["att_errors"][
            "security_gate_error"
        ] = "insufficient_encryption"
        self.assertEqual(contract_error_code(validate_protocol, candidate),
                         "SECURITY")

    def test_scan_rssi_range_and_timeout_failures(self) -> None:
        field = self.protocol["types"]["scan_network"]["fields"][-1]
        self.assertEqual((field["min"], field["max"]), (-127, 127))
        matrix = self.protocol["wire_rules"]["operation_result"][
            "failure_matrix"
        ]
        for operation in ("SET_CREDENTIALS", "DISCONNECT", "FORGET"):
            with self.subTest(operation=operation):
                self.assertIn("TIMEOUT", matrix[operation])

    def test_scan_rssi_range_is_normative(self) -> None:
        candidate = copy.deepcopy(self.protocol)
        candidate["types"]["scan_network"]["fields"][-1]["max"] = 0
        self.assertEqual(contract_error_code(validate_protocol, candidate),
                         "VALUE")

    def test_field_rule_and_low_mtu_links_are_enforced(self) -> None:
        mutations = [
            lambda p: p["protocol"]["limits"].__setitem__(
                "max_scan_networks", 4
            ),
            lambda p: p["types"]["scan_network"]["fields"][0].__setitem__(
                "min_bytes", 0
            ),
            lambda p: p["wire_rules"]["text"]["text_rules"][
                "password"
            ].__setitem__("min_octet", 0x21),
            lambda p: next(command for command in p["commands"]
                           if command["name"] == "GET_STATUS").__setitem__(
                               "requires_full_mtu", False
                           ),
            lambda p: next(command for command in p["commands"]
                           if command.get("response_semantic") ==
                           "link_info").__setitem__(
                               "requires_full_mtu", True
                           ),
        ]
        for mutation in mutations:
            candidate = copy.deepcopy(self.protocol)
            mutation(candidate)
            with self.subTest(mutation=mutation):
                self.assertIn(
                    contract_error_code(validate_protocol, candidate),
                    {"STATUS", "VALUE", "TRANSPORT_MATH"},
                )

    def test_async_operation_id_and_terminal_event_links_are_enforced(self) -> None:
        candidate = copy.deepcopy(self.protocol)
        scan = next(command for command in candidate["commands"]
                    if command["name"] == "SCAN")
        scan["response"][0]["nonzero"] = False
        self.assertEqual(contract_error_code(validate_protocol, candidate),
                         "OPERATION")

        candidate = copy.deepcopy(self.protocol)
        event = next(event for event in candidate["events"]
                     if event["name"] == "SCAN_COMPLETE")
        event["payload"][0]["nonzero"] = False
        self.assertEqual(contract_error_code(validate_protocol, candidate),
                         "OPERATION")

        candidate = copy.deepcopy(self.protocol)
        scan = next(command for command in candidate["commands"]
                    if command["name"] == "SCAN")
        scan["completion_event"] = next(
            event["name"] for event in candidate["events"]
            if event.get("payload_semantic") == "operation_result"
        )
        self.assertEqual(contract_error_code(validate_protocol, candidate),
                         "OPERATION")

        candidate = copy.deepcopy(self.protocol)
        scan = next(command for command in candidate["commands"]
                    if command["name"] == "SCAN")
        scan["allowed_statuses"].remove("INTERNAL")
        self.assertEqual(contract_error_code(validate_protocol, candidate),
                         "STATUS")

        candidate = copy.deepcopy(self.protocol)
        operation_query = next(
            command for command in candidate["commands"]
            if command.get("response_semantic") == "operation_record"
        )
        operation_query["allowed_statuses"].remove("INVALID_ARGUMENT")
        self.assertEqual(contract_error_code(validate_protocol, candidate),
                         "STATUS")

    def test_declared_maximum_message_sizes_are_current(self) -> None:
        limits = self.protocol["protocol"]["limits"]
        self.assertEqual(limits["maximum_get_info_response_bytes"], 11)
        self.assertEqual(limits["maximum_scan_event_bytes"], 183)
        self.assertEqual(limits["maximum_get_operation_response_bytes"], 186)


class ContractBoundaryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.protocol = load_protocol()
        self.vectors = load_vectors()

    def test_wifi_implementation_policy_keys_are_not_normative(self) -> None:
        rules = self.protocol["wire_rules"]
        self.assertNotIn("admission", rules)
        self.assertNotIn("scan", rules)
        self.assertNotIn("failure_rollback_required",
                         rules["operation_result"])
        self.assertIn("delivery", rules["wifi_status"])
        self.assertNotIn("intermediate_updates", rules["wifi_status"])

    def test_policy_fields_cannot_be_added_to_schema(self) -> None:
        mutations = [
            lambda p: p["wire_rules"].__setitem__(
                "automatic_reconnect", {"enabled": True}
            ),
            lambda p: p["wire_rules"]["scan_result"].__setitem__(
                "sort", ["rssi_descending"]
            ),
            lambda p: p["wire_rules"]["operation_result"].__setitem__(
                "failure_rollback_required", False
            ),
        ]
        for mutation in mutations:
            candidate = copy.deepcopy(self.protocol)
            mutation(candidate)
            with self.subTest(mutation=mutation):
                self.assertEqual(
                    contract_error_code(validate_protocol, candidate),
                    "UNKNOWN_FIELD",
                )

    def test_status_and_scan_policies_are_not_weakened(self) -> None:
        candidate = copy.deepcopy(self.protocol)
        candidate["wire_rules"]["wifi_status"]["delivery"][
            "ordinary_updates"
        ] = "all"
        self.assertEqual(contract_error_code(validate_protocol, candidate),
                         "OPERATION")

        candidate = copy.deepcopy(self.protocol)
        candidate["wire_rules"]["wifi_status"]["delivery"][
            "terminal_event_priority"
        ] = False
        self.assertEqual(contract_error_code(validate_protocol, candidate),
                         "OPERATION")

        candidate = copy.deepcopy(self.protocol)
        candidate["wire_rules"]["wifi_status"]["delivery"][
            "ordinary_updates_while_terminal_pending"
        ] = "send"
        self.assertEqual(contract_error_code(validate_protocol, candidate),
                         "OPERATION")

        candidate = copy.deepcopy(self.protocol)
        candidate["wire_rules"]["scan_result"]["count_after_filter"] = False
        self.assertEqual(contract_error_code(validate_protocol, candidate),
                         "VALUE")

        candidate = copy.deepcopy(self.protocol)
        candidate["wire_rules"]["scan_result"]["representable_security"][
            "PERSONAL"
        ] = ["WIFI_AUTH_WPA2_PSK"]
        self.assertEqual(contract_error_code(validate_protocol, candidate),
                         "VALUE")

        candidate = copy.deepcopy(self.protocol)
        candidate["enums"]["wifi_security"]["WEP"] = 3
        self.assertEqual(contract_error_code(validate_protocol, candidate),
                         "ENUM")

        candidate = copy.deepcopy(self.protocol)
        candidate["enums"]["wifi_security"] = {"WEP": 1, "PERSONAL": 2}
        self.assertEqual(contract_error_code(validate_protocol, candidate),
                         "ENUM")

        candidate = copy.deepcopy(self.protocol)
        candidate["enums"]["wifi_security"] = {"OPEN": 2, "PERSONAL": 1}
        self.assertEqual(contract_error_code(validate_protocol, candidate),
                         "ENUM")

        candidate = copy.deepcopy(self.protocol)
        candidate["wire_rules"]["operation_lifecycle"][
            "finite_termination_required"
        ] = False
        self.assertEqual(contract_error_code(validate_protocol, candidate),
                         "OPERATION")

    def test_operation_lifecycle_regressions_are_rejected(self) -> None:
        mutations = [
            lambda p: p["wire_rules"]["operation_lifecycle"].__setitem__(
                "terminal_event_replay", True
            ),
            lambda p: p["wire_rules"]["operation_lifecycle"].__setitem__(
                "accepted_response_disconnect_policy", "replay"
            ),
            lambda p: p["wire_rules"]["operation_lifecycle"].__setitem__(
                "disconnect_clears_record", True
            ),
            lambda p: p["wire_rules"]["operation_lifecycle"].__setitem__(
                "ack_terminal_clears_record", False
            ),
            lambda p: p["wire_rules"]["operation_lifecycle"].__setitem__(
                "must_reach_terminal", False
            ),
            lambda p: p["wire_rules"]["operation_lifecycle"].__setitem__(
                "ack_requires_terminal_event_confirmation", False
            ),
            lambda p: p["wire_rules"]["operation_lifecycle"].__setitem__(
                "ack_clears_after_response_confirmation", False
            ),
            lambda p: p["wire_rules"]["operation_record"].__setitem__(
                "failed_result_count", 1
            ),
            lambda p: p["wire_rules"]["operation_record"].__setitem__(
                "scan_results_phase",
                p["wire_rules"]["operation_record"]["failed_phase"],
            ),
        ]
        for mutation in mutations:
            candidate = copy.deepcopy(self.protocol)
            mutation(candidate)
            with self.subTest(mutation=mutation):
                self.assertEqual(
                    contract_error_code(validate_protocol, candidate),
                    "OPERATION",
                )

    def test_operation_failure_matrix_and_wifi_edges_are_linked(self) -> None:
        candidate = copy.deepcopy(self.protocol)
        candidate["wire_rules"]["operation_result"]["failure_matrix"][
            "SET_CREDENTIALS"
        ].append("AUTHENTICATION")
        self.assertEqual(contract_error_code(validate_vectors, candidate,
                                             self.vectors), "EXPECTATION")

        candidate = copy.deepcopy(self.protocol)
        connect = next(command for command in candidate["commands"]
                       if command["name"] == "CONNECT")
        connect["allowed_statuses"].remove("NOT_FOUND")
        self.assertEqual(contract_error_code(validate_protocol, candidate),
                         "STATUS")


class VectorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.protocol = load_protocol()
        self.vectors = load_vectors()

    def test_every_valid_message_decodes(self) -> None:
        for case in self.vectors["messages"]["valid"]:
            with self.subTest(case=case["id"]):
                validate_message(self.protocol, case)

    def test_application_error_envelope_decodes_offending_opcode(self) -> None:
        case = next(item for item in self.vectors["messages"]["valid"]
                    if item["kind"] == "application_error")
        self.assertEqual(validate_message(self.protocol, case),
                         {"offending_opcode": 0x70})

    def test_every_negative_message_has_the_expected_error(self) -> None:
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

    def test_wrong_negative_expectation_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.vectors)
        candidate["messages"]["invalid"][0]["expected_error"] = "UTF8"
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, candidate),
            "EXPECTATION",
        )

    def test_command_and_event_vector_coverage_is_enforced(self) -> None:
        candidate = copy.deepcopy(self.vectors)
        candidate["messages"]["valid"] = [
            item for item in candidate["messages"]["valid"]
            if item["id"] != "ack-operation-request"
        ]
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, candidate),
            "COVERAGE",
        )

        candidate = copy.deepcopy(self.vectors)
        candidate["messages"]["valid"] = [
            item for item in candidate["messages"]["valid"]
            if item["id"] != "unknown-opcode-error"
        ]
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, candidate),
            "COVERAGE",
        )

        candidate = copy.deepcopy(self.vectors)
        candidate["messages"]["valid"] = [
            item for item in candidate["messages"]["valid"]
            if item["id"] != "get-operation-connect-failed"
        ]
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, candidate),
            "COVERAGE",
        )

    def test_disconnect_recovery_expectations_are_checked(self) -> None:
        candidate = copy.deepcopy(self.vectors)
        scenario = candidate["operation_cases"][0]
        active_ack = next(
            step for step in scenario["steps"]
            if step["action"] == "ack" and step["operation_id"] == 1
        )
        active_ack["expect"] = "OK"
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, candidate),
            "EXPECTATION",
        )

    def test_operation_recovery_scenario_coverage_is_enforced(self) -> None:
        candidate = copy.deepcopy(self.vectors)
        candidate["operation_cases"] = candidate["operation_cases"][1:]
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, candidate),
            "COVERAGE",
        )

    def test_routing_and_result_matrix_expectations_are_checked(self) -> None:
        candidate = copy.deepcopy(self.vectors)
        candidate["routing_cases"][0]["expect"] = "ATT:value_not_allowed"
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, candidate),
            "EXPECTATION",
        )

        candidate = copy.deepcopy(self.vectors)
        candidate["result_matrix_cases"][0]["allowed_failures"].pop()
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, candidate),
            "EXPECTATION",
        )

        candidate = copy.deepcopy(self.vectors)
        candidate["routing_cases"] = [
            case for case in candidate["routing_cases"]
            if case["id"] != "get-operation-low-mtu"
        ]
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, candidate),
            "COVERAGE",
        )

    def test_ack_is_not_committed_before_response_confirmation(self) -> None:
        candidate = copy.deepcopy(self.vectors)
        scenario = candidate["operation_cases"][0]
        scenario["steps"] = [
            step for step in scenario["steps"]
            if step["action"] != "confirm_ack"
        ]
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, candidate),
            "EXPECTATION",
        )

    def test_duplicate_operation_id_and_terminal_event_are_rejected(self) -> None:
        candidate = copy.deepcopy(self.vectors)
        scenario = candidate["operation_cases"][0]
        scenario["steps"].extend([
            {"action": "accept", "operation": "SCAN", "operation_id": 1,
             "expect": "ACCEPTED"},
        ])
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, candidate),
            "OPERATION",
        )

        candidate = copy.deepcopy(self.vectors)
        scenario = candidate["operation_cases"][0]
        confirm_index = next(
            index for index, step in enumerate(scenario["steps"])
            if step["action"] == "confirm_terminal"
        )
        scenario["steps"].insert(confirm_index + 1, {
            "action": "emit_terminal", "operation_id": 1,
            "operation": "CONNECT", "event": "OPERATION_COMPLETE",
        })
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, candidate),
            "EXPECTATION",
        )

        candidate = copy.deepcopy(self.vectors)
        scenario = candidate["operation_cases"][0]
        status_index = next(
            index for index, step in enumerate(scenario["steps"])
            if step["action"] == "emit_status"
        )
        scenario["steps"].insert(status_index, {
            "action": "queue_ordinary_status", "snapshot": "IDLE",
        })
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, candidate),
            "EXPECTATION",
        )

        candidate = copy.deepcopy(self.vectors)
        scenario = candidate["operation_cases"][0]
        terminal = next(step for step in scenario["steps"]
                        if step["action"] == "emit_terminal")
        terminal["operation_id"] = 2
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, candidate),
            "EXPECTATION",
        )

    def test_operation_scenario_recovery_boundaries_are_enforced(self) -> None:
        candidate = copy.deepcopy(self.vectors)
        scenario = candidate["operation_cases"][0]
        rejected = next(
            step for step in scenario["steps"]
            if step["action"] == "accept" and step["expect"] == "BUSY"
        )
        rejected["operation_id"] = 2
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, candidate),
            "OPERATION",
        )

        candidate = copy.deepcopy(self.vectors)
        scenario = next(
            item for item in candidate["operation_cases"]
            if item["id"] ==
            "remaining-operation-successes-and-event-disconnect"
        )
        complete_index = next(
            index for index, step in enumerate(scenario["steps"])
            if step["action"] == "complete" and step["operation_id"] == 12
        )
        del scenario["steps"][complete_index + 1:complete_index + 3]
        scenario["steps"].insert(complete_index + 1, {
            "action": "query", "expect": "SUCCEEDED", "operation_id": 12,
            "operation": "DISCONNECT", "failure": "NONE",
        })
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, candidate),
            "EXPECTATION",
        )

        candidate = copy.deepcopy(self.vectors)
        scan_case = next(item for item in candidate["wifi_cases"]
                         if item["case"] == "scan_filtering")
        scan_case["expect"]["filtered_ssids"].reverse()
        validate_vectors(self.protocol, candidate)

        candidate = copy.deepcopy(self.vectors)
        scenario = next(
            item for item in candidate["operation_cases"]
            if item["id"] == "disconnect-completion-recovery-and-ack"
        )
        ack_indexes = [
            index for index, step in enumerate(scenario["steps"])
            if step["action"] == "ack" and step["expect"] == "OK"
        ]
        second_ack = ack_indexes[1]
        del scenario["steps"][second_ack - 2:second_ack]
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, candidate),
            "EXPECTATION",
        )

        candidate = copy.deepcopy(self.vectors)
        scenario = next(item for item in candidate["operation_cases"]
                        if item["id"] == "id-exhaustion-and-reboot")
        scenario["steps"][0]["operation_id"] = (1 << 32) - 2
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, candidate),
            "EXPECTATION",
        )

        candidate = copy.deepcopy(self.vectors)
        scenario = next(item for item in candidate["operation_cases"]
                        if item["id"] == "id-exhaustion-and-reboot")
        connect_index = next(
            index for index, step in enumerate(scenario["steps"])
            if step["action"] == "accept" and
            step["operation"] == "CONNECT"
        )
        del scenario["steps"][connect_index:connect_index + 4]
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, candidate),
            "COVERAGE",
        )

        candidate = copy.deepcopy(self.vectors)
        scenario = next(item for item in candidate["operation_cases"]
                        if item["id"] == "ordinary-status-coalesce-and-disconnect")
        scenario["steps"][2]["snapshot"] = "IDLE"
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, candidate),
            "EXPECTATION",
        )


    def test_scan_filter_count_and_rssi_boundaries_are_covered(self) -> None:
        valid_ids = {item["id"] for item in self.vectors["messages"]["valid"]}
        invalid_ids = {
            item["id"] for item in self.vectors["messages"]["invalid"]
        }
        self.assertIn("scan-rssi-lower-bound", valid_ids)
        self.assertIn("scan-rssi-below-lower-bound", invalid_ids)

        candidate = copy.deepcopy(self.vectors)
        scan_case = next(
            item for item in candidate["wifi_cases"]
            if item["case"] == "scan_filtering_under_limit"
        )
        scan_case["expect"]["count"] = 3
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, candidate),
            "EXPECTATION",
        )

    def test_accepted_response_disconnect_recovery_requires_query(self) -> None:
        candidate = copy.deepcopy(self.vectors)
        scenario = next(
            item for item in candidate["operation_cases"]
            if item["id"] == "accepted-response-disconnect-recovery"
        )
        query_index = next(
            index for index, step in enumerate(scenario["steps"])
            if step["action"] == "query"
        )
        scenario["steps"].insert(query_index, {
            "action": "ack", "operation_id": 50, "expect": "OK",
        })
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, candidate),
            "EXPECTATION",
        )

    def test_terminal_priority_defers_ordinary_status_emission(self) -> None:
        candidate = copy.deepcopy(self.vectors)
        scenario = next(
            item for item in candidate["operation_cases"]
            if item["id"] == "ordinary-status-deferred-by-terminal"
        )
        terminal_index = next(
            index for index, step in enumerate(scenario["steps"])
            if step["action"] == "emit_terminal"
        )
        scenario["steps"].insert(terminal_index, {
            "action": "emit_ordinary_status", "snapshot": "IDLE",
        })
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, candidate),
            "EXPECTATION",
        )

        candidate = copy.deepcopy(self.vectors)
        scenario = next(
            item for item in candidate["operation_cases"]
            if item["id"] == "final-status-ordinary-deferred"
        )
        terminal_index = next(
            index for index, step in enumerate(scenario["steps"])
            if step["action"] == "emit_terminal"
        )
        scenario["steps"].insert(terminal_index, {
            "action": "emit_ordinary_status", "snapshot": "ERROR",
        })
        self.assertEqual(
            contract_error_code(validate_vectors, self.protocol, candidate),
            "EXPECTATION",
        )


if __name__ == "__main__":
    unittest.main()
