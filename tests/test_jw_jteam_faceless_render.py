"""Safely validate an original zero-footage video editorial input without paid calls."""
import json
import tempfile
import unittest
from pathlib import Path
from scripts.jw_jteam_faceless_render import validate_episode, DEFAULT_EPISODE


class OwnerOnlyFacelessRenderTests(unittest.TestCase):
    def test_original_fixture_has_five_unique_scopes(self):
        item=validate_episode(DEFAULT_EPISODE)
        self.assertEqual(item["publication"],"DRAFT_ONLY")
        self.assertEqual(item["rights"],"PROJECT_ORIGINAL_TEXT_AND_PROGRAMMATIC_GRAPHICS")
        self.assertEqual(len({s["title"] for s in item["slides"]}),5)
        self.assertEqual(item["aspect_ratio"],"9:16")

    def test_publication_cannot_be_self_approved(self):
        obj=validate_episode(DEFAULT_EPISODE)
        obj["publication"]="PUBLIC"
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/"bad.json"
            source.write_text(json.dumps(obj),encoding="utf-8")
            with self.assertRaisesRegex(ValueError,"INVALID_EPISODE_POLICY"):
                validate_episode(source)

    def test_incomplete_scene_fails_closed(self):
        obj=validate_episode(DEFAULT_EPISODE)
        obj["slides"][2]["points"].pop()
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/"bad.json"
            source.write_text(json.dumps(obj),encoding="utf-8")
            with self.assertRaisesRegex(ValueError,"INVALID_SCENE_POINTS"):
                validate_episode(source)

    def test_symlink_cannot_be_used_as_episode_input(self):
        with tempfile.TemporaryDirectory() as d:
            linked=Path(d)/"link.json"
            linked.symlink_to(DEFAULT_EPISODE)
            with self.assertRaisesRegex(ValueError,"UNSAFE_EPISODE_PATH"):
                validate_episode(linked)


if __name__=="__main__":
    unittest.main()
