from __future__ import annotations

import json
import pathlib
import unittest


DIRECTORY = pathlib.Path(__file__).parent


class EnvironmentManifestTests(unittest.TestCase):
    def test_all_five_environment_classes_are_defined(self) -> None:
        documents = [json.loads(path.read_text(encoding="utf-8")) for path in DIRECTORY.glob("*.json")]
        self.assertEqual(len(documents), 5)
        classes = {document["environment_class"] for document in documents}
        self.assertEqual(
            classes,
            {"simulation", "local_lab", "staging_real_onion", "multi_region_staging", "adversarial"},
        )
        for document in documents:
            self.assertEqual(document["schema_version"], 1)
            self.assertTrue(document["topology"])
            self.assertTrue(document["capabilities"])
            self.assertTrue(document["required_evidence"])
            if document["release_evidence"]:
                self.assertNotIn(document["environment_class"], {"simulation", "local_lab"})


if __name__ == "__main__":
    unittest.main()
