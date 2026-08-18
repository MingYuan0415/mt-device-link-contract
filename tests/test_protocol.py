from __future__ import annotations

import json
import unittest
from pathlib import Path

from tooling.check import (ContractError, load_protocol, validate_protocol,
                           validate_vector, validate_vectors)


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


if __name__ == "__main__":
    unittest.main()
