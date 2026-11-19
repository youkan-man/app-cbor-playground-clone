"""Auto input, damaged captures, history and candidate inspection as one flow."""
import json
import tempfile
import unittest

from starlette.testclient import TestClient

from app import create_app


class AutoInputAPITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.client = TestClient(create_app(self.temp.name))

    def tearDown(self):
        self.client.close()
        self.temp.cleanup()

    def analyze(self, source, **options):
        response = self.client.post("/api/analyze", json={"text": source, **options})
        self.assertEqual(response.status_code, 201, response.text)
        record = response.json()
        self.assertEqual(record["source"], source)
        self.assertIn("input", record["result"])
        self.assertNotIn("data", record["result"]["input"])
        return record

    def test_omitted_format_is_detected_and_saved(self):
        record = self.analyze('{"a":1}')
        self.assertEqual(record["hex"], "a1616101")
        self.assertEqual(record["result"]["input"]["format"], "json")
        self.assertEqual(record["result"]["input"]["requested_format"], "auto")
        self.assertEqual(record["result"]["selected"]["json"], [{"a": 1}])
        saved = self.client.get("/api/history/" + record["id"]).json()
        self.assertEqual(saved["result"]["input"], record["result"]["input"])

    def test_selected_format_mismatch_is_recovered(self):
        record = self.analyze('{"a":1}', format="hex")
        self.assertEqual(record["hex"], "a1616101")
        self.assertEqual(record["result"]["input"]["requested_format"], "hex")
        self.assertEqual(record["result"]["input"]["format"], "json")

    def test_normalize_does_not_add_history(self):
        source = "2026-11-19 13:00:00 RX: 82 01 02"
        response = self.client.post("/api/normalize", json={"text": source, "format": "auto"})
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual(result["hex"], "820102")
        self.assertIn("input", result)
        self.assertNotIn("data", result["input"])
        self.assertEqual(self.client.get("/api/history").json(), [])
        record = self.analyze(source)
        self.assertEqual(record["hex"], result["hex"])
        self.assertEqual(record["result"]["input"]["segments"], result["input"]["segments"])

    def test_auto_detection_does_not_disable_all_offset_scanning(self):
        record = self.analyze("ff 1c 82 01 02 ff")
        result = record["result"]
        self.assertEqual(record["hex"], "ff1c820102ff")
        self.assertEqual(result["tested"], 6)
        self.assertEqual(result["best"]["offset"], 2)
        self.assertEqual(result["best"]["hits"], 3)
        self.assertEqual(result["selected"]["json"], [[1, 2]])

    def test_unrecognized_text_and_zero_hit_input_are_saved(self):
        text = "not CBOR — 日本語"
        record = self.analyze(text)
        self.assertEqual(record["hex"], text.encode("utf-8").hex())
        self.assertEqual(record["result"]["input"]["format"], "text")
        failed = self.analyze("ff ff ff")
        self.assertIsNone(failed["result"]["best"])
        self.assertEqual(failed["result"]["selected"]["hits"], 0)
        self.assertEqual(failed["result"]["selected"]["rows"], [])
        self.assertEqual(len(self.client.get("/api/history").json()), 2)

    def test_truncated_cbor_still_finds_later_offsets(self):
        record = self.analyze("82 01")
        self.assertEqual(record["hex"], "8201")
        self.assertEqual(record["result"]["best"]["offset"], 1)
        self.assertEqual(record["result"]["selected"]["json"], [1])

    def test_damaged_input_does_not_manufacture_an_array(self):
        record = self.analyze("82 01 ZZ 02")
        result = record["result"]
        self.assertEqual(record["hex"], "820102")
        self.assertEqual(result["tested"], 3)
        self.assertEqual(result["best"]["hits"], 1)
        self.assertTrue(result["input"]["warnings"])
        self.assertFalse(any(item["offset"] == 0 for item in result["candidates"]))
        url = "/api/history/" + record["id"]
        self.assertEqual(self.client.get(url + "/node?offset=0").status_code, 400)
        response = self.client.post(url + "/candidate", json={"offset": 0})
        self.assertEqual(response.status_code, 200, response.text)
        selected = response.json()["result"]["selected"]
        self.assertEqual(selected["hits"], 0)
        self.assertEqual(selected["rows"], [])
        self.assertEqual(selected["json"], [])
        self.assertIsNotNone(selected["error"])

    def test_segment_offsets_node_inspection_and_selection_are_consistent(self):
        record = self.analyze("82 01 ZZ 83 01 02 03")
        result = record["result"]
        self.assertEqual(record["hex"], "820183010203")
        self.assertEqual(result["best"]["offset"], 2)
        self.assertEqual(result["best"]["hits"], 4)
        self.assertEqual([(row["start"], row["end"]) for row in result["selected"]["rows"]],
                         [(2, 6), (3, 4), (4, 5), (5, 6)])
        url = "/api/history/" + record["id"]
        response = self.client.get(url + "/node?offset=2")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["hex"], "83010203")
        self.assertEqual(response.json()["json"], [1, 2, 3])
        selected = self.client.post(url + "/candidate", json={"offset": 1})
        self.assertEqual(selected.status_code, 200, selected.text)
        reopened = self.client.get(url).json()
        self.assertEqual(reopened["result"]["selected"]["offset"], 1)
        self.assertEqual(reopened["result"]["selected"]["json"], [1])
        self.assertEqual(reopened["result"]["input"], result["input"])

    def test_sequence_cannot_cross_unknown_data(self):
        record = self.analyze("01 02 ZZ 03 04", sequence=True)
        result = record["result"]
        self.assertEqual(result["tested"], 4)
        self.assertEqual(result["best"]["offset"], 0)
        self.assertEqual(result["best"]["hits"], 2)
        self.assertEqual(result["selected"]["end"], 2)
        self.assertEqual(result["selected"]["json"], [1, 2])

    def test_exact_offset_uses_global_extracted_byte_offsets(self):
        record = self.analyze("01 ZZ 82 01 02", mode="exact", offset=1)
        self.assertEqual(record["result"]["selected"]["offset"], 1)
        self.assertEqual(record["result"]["selected"]["json"], [[1, 2]])
        self.assertEqual(record["result"]["selected"]["rows"][0]["start"], 1)

    def test_comparison_uses_decoded_values_after_input_recovery(self):
        left = self.analyze("82 01 ZZ 83 01 02 03")
        right = self.analyze("83 01 02 03")
        response = self.client.post("/api/compare", json={"left": left["id"], "right": right["id"]})
        self.assertEqual(response.status_code, 200, response.text)
        counts = response.json()["counts"]
        self.assertEqual(counts["changed"], 0)
        self.assertEqual(counts["added"], 0)
        self.assertEqual(counts["removed"], 0)
        self.assertEqual(counts["same"], 4)

    def test_input_metadata_survives_database_reopen_and_reanalysis(self):
        record = self.analyze("82 01 ZZ 83 01 02 03", format="hex")
        with TestClient(create_app(self.temp.name)) as other:
            reopened = other.get("/api/history/" + record["id"]).json()
            self.assertEqual(reopened["source"], record["source"])
            self.assertEqual(reopened["hex"], record["hex"])
            self.assertEqual(reopened["result"]["input"], record["result"]["input"])
            response = other.post("/api/analyze", json={
                "text": reopened["source"],
                "format": reopened["result"]["input"]["requested_format"],
            })
            self.assertEqual(response.status_code, 201, response.text)
            replay = response.json()
            self.assertEqual(replay["hex"], record["hex"])
            self.assertEqual(replay["result"]["input"]["segments"], record["result"]["input"]["segments"])

    def test_binary_transport_preserves_every_byte_and_export(self):
        raw = bytes(range(256))
        record = self.analyze(raw.hex(), format="binary")
        self.assertEqual(record["hex"], raw.hex())
        self.assertEqual(record["result"]["tested"], len(raw))
        response = self.client.get("/api/history/" + record["id"] + "/export?format=cbor")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, raw)

    def test_empty_input_is_not_saved(self):
        response = self.client.post("/api/analyze", json={"text": ""})
        self.assertEqual(response.status_code, 400, response.text)
        self.assertEqual(self.client.get("/api/history").json(), [])

    def test_oversized_byte_literal_is_retained_as_text(self):
        source = "new Uint8Array([" + "9" * 5000 + "])"
        record = self.analyze(source)
        self.assertEqual(record["result"]["input"]["format"], "text")
        self.assertEqual(record["hex"], source.encode("utf-8").hex())

    def test_invalid_format_types_return_400_instead_of_500(self):
        for route in ["/api/analyze", "/api/normalize"]:
            for preferred in [[], {}]:
                with self.subTest(route=route, preferred=preferred):
                    response = self.client.post(route, json={"text": "820102", "format": preferred})
                    self.assertEqual(response.status_code, 400, response.text)
        self.assertEqual(self.client.get("/api/history").json(), [])

    def test_unpaired_surrogate_source_survives_save_reopen_and_json_export(self):
        source = chr(0xD800)
        # Send JSON's legal escaped representation. httpx's json= encoder can
        # reject an unpaired surrogate before it reaches the application.
        response = self.client.post("/api/analyze", content=json.dumps({"text": source}),
                                    headers={"Content-Type": "application/json"})
        self.assertEqual(response.status_code, 201, response.text)
        record = response.json()
        self.assertEqual(record["source"], source)
        self.assertEqual(record["hex"], source.encode("utf-8", "surrogatepass").hex())
        url = "/api/history/" + record["id"]
        with TestClient(create_app(self.temp.name)) as other:
            reopened = other.get(url)
            self.assertEqual(reopened.status_code, 200, reopened.text)
            self.assertEqual(reopened.json()["source"], source)
            self.assertEqual(reopened.json()["hex"], record["hex"])
            exported = other.get(url + "/export?format=json")
            self.assertEqual(exported.status_code, 200, exported.text)
            self.assertEqual(exported.json()["source"], source)
            self.assertEqual(exported.json()["hex"], record["hex"])


if __name__ == "__main__":
    unittest.main()
