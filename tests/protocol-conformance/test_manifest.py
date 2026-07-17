from __future__ import annotations

import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class ProtocolConformanceManifestTests(unittest.TestCase):
    def test_manifest_references_real_bounded_suites(self) -> None:
        manifest = json.loads((pathlib.Path(__file__).parent / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["protocol"], "onionroute-gateway-v1")
        covered: set[str] = set()
        for suite in manifest["suites"]:
            cargo = ROOT / suite["manifest"]
            test = cargo.parent / "tests" / f"{suite['test']}.rs"
            self.assertTrue(cargo.is_file(), cargo)
            self.assertTrue(test.is_file(), test)
            covered.update(suite["covers"])
        self.assertTrue({"bounded-allocation", "backpressure", "version-downgrade", "redaction"} <= covered)
        for target in manifest["fuzz_targets"]:
            self.assertTrue((ROOT / target).is_file(), target)

    def test_reference_decoder_rejects_before_body_allocation(self) -> None:
        source = (ROOT / "crates/gateway-protocol/src/framing.rs").read_text(encoding="utf-8")
        size_check = source.index("if length > self.maximum_frame_size")
        allocation = source.index("self.body = Vec::with_capacity(length)")
        self.assertLess(size_check, allocation)
        self.assertIn("ABSOLUTE_MAX_FRAME_SIZE", source)
        self.assertIn("NonCanonicalVarint", source)


if __name__ == "__main__":
    unittest.main()
