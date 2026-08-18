from __future__ import annotations

import json
import unittest
from pathlib import Path

import yaml

from tooling.check import (ContractError, load_protocol, normalized_digest,
                           validate_att_mtu, validate_protocol, validate_vector,
                           validate_vectors)


ROOT = Path(__file__).resolve().parents[1]


class ProtocolTest(unittest.TestCase):
    def setUp(self) -> None:
        self.protocol = load_protocol()

    def test_protocol_is_valid(self) -> None:
        validate_protocol(self.protocol)
        validate_vectors(self.protocol)

    def test_unknown_status_is_rejected(self) -> None:
        vectors = json.loads((ROOT / "vectors/golden.json").read_text())
        case = next(item for item in vectors["cases"] if item["id"] == "get-info-response")
        case["status"] = "UNKNOWN"
        with self.assertRaises(ContractError):
            validate_vector(self.protocol, case)

    def test_low_mtu_vector_is_rejected(self) -> None:
        vectors = json.loads((ROOT / "vectors/golden.json").read_text())
        case = next(item for item in vectors["cases"] if item["id"] == "get-info-request")
        case["hex"] = "03"
        with self.assertRaises(ContractError):
            validate_vector(self.protocol, case)
        with self.assertRaises(ContractError):
            validate_att_mtu(246)
        validate_att_mtu(247)

    def test_truncated_payload_is_rejected(self) -> None:
        vectors = json.loads((ROOT / "vectors/golden.json").read_text())
        case = next(item for item in vectors["cases"] if item["id"] == "get-info-response")
        case["hex"] = "03010100"
        with self.assertRaises(ContractError):
            validate_vector(self.protocol, case)

    def test_vectors_cover_all_commands_and_unknown_opcode(self) -> None:
        vectors = json.loads((ROOT / "vectors/golden.json").read_text())
        request_opcodes = {
            item["opcode"] for item in vectors["cases"] if item["kind"] == "request"
        }
        self.assertEqual(set(range(1, 10)), request_opcodes)
        unknown = next(item for item in vectors["cases"] if item["id"] == "unknown-operation")
        self.assertEqual(127, unknown["opcode"])
        self.assertEqual("UNSUPPORTED", unknown["status"])

    def test_digest_is_independent_of_json_whitespace(self) -> None:
        digest = normalized_digest(self.protocol)
        compact = json.dumps(self.protocol, separators=(",", ":"), sort_keys=True)
        pretty = json.dumps(self.protocol, indent=2, sort_keys=True)
        self.assertEqual(
            digest,
            __import__("hashlib").sha256(
                json.dumps(json.loads(compact), sort_keys=True, separators=(",", ":"))
                .encode()
            ).hexdigest(),
        )
        self.assertNotEqual(compact, pretty)
        yaml_text = (ROOT / "protocol.yaml").read_text(encoding="utf-8")
        crlf_protocol = yaml.safe_load(yaml_text.replace("\n", "\r\n"))
        self.assertEqual(digest, normalized_digest(crlf_protocol))


if __name__ == "__main__":
    unittest.main()
