from __future__ import annotations

import json
import pathlib
import unittest


class LeakEvidenceMatrixTests(unittest.TestCase):
    def test_required_vectors_modes_and_transition_states_are_complete(self) -> None:
        document = json.loads((pathlib.Path(__file__).parent / "scenario-matrix.json").read_text(encoding="utf-8"))
        self.assertEqual(set(document["modes"]), {"standard", "enhanced", "maximum", "direct_tor"})
        self.assertEqual(
            set(document["states"]),
            {"startup", "connected", "shutdown", "soft_rotation", "hard_rotation", "reconnecting"},
        )
        self.assertEqual(
            {item["id"] for item in document["vectors"]},
            {"LEAK-DNS", "LEAK-IPV4", "LEAK-IPV6", "LEAK-WEBRTC", "LEAK-QUIC", "LEAK-DOH", "LEAK-DOT", "LEAK-APP", "LEAK-LAN", "LEAK-TRANSITION"},
        )
        for vector in document["vectors"]:
            self.assertTrue(vector["required"])


if __name__ == "__main__":
    unittest.main()
