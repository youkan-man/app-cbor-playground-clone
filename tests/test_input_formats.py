"""Input recognition must accept real captures without inventing wire bytes."""
import base64
import unittest

from cbor_codec import CBORError, decode_input
from input_formats import parse_input


class InputFormatTests(unittest.TestCase):
    def parsed(self, text, preferred="auto"):
        result = parse_input(text, preferred)
        self.assertIsInstance(result["data"], bytes)
        self.assertIsInstance(result["format"], str)
        self.assertIsInstance(result["label"], str)
        self.assertIsInstance(result["warnings"], list)
        self.assertTrue(all(isinstance(item, str) for item in result["warnings"]))
        self.assertTrue(result["segments"])
        position = 0
        for segment in result["segments"]:
            self.assertEqual(segment["start"], position)
            self.assertGreater(segment["end"], position)
            self.assertLessEqual(segment["end"], len(result["data"]))
            position = segment["end"]
        self.assertEqual(position, len(result["data"]))
        return result

    def test_hex_bytes_with_common_separators(self):
        for source in [
            "820102", "82 01 02", "82\t01\r\n02", "0x82, 0x01, 0x02",
            "82:01:02", "82-01-02", "82_01_02", "\ufeff82\u300001\r\n02",
        ]:
            with self.subTest(source=source):
                result = self.parsed(source)
                self.assertEqual(result["data"], bytes.fromhex("820102"))
                self.assertEqual(result["format"], "hex")
                self.assertEqual(len(result["segments"]), 1)

    def test_escaped_bytes(self):
        for source in [r"\x82\x01\x02", r"b'\x82\x01\x02'"]:
            with self.subTest(source=source):
                self.assertEqual(self.parsed(source)["data"], bytes.fromhex("820102"))

    def test_dump_offset_and_ascii_are_not_payload(self):
        for source in [
            "00000000: 82 01 02  |...|",
            "00000000  82 01 02                                          |...|",
            "00000000: 8201 02  ...",
            "00000000: 82 01\n00000002: 02",
            "00000100: 82 01 02  |...|",
        ]:
            with self.subTest(source=source):
                result = self.parsed(source)
                self.assertEqual(result["data"], bytes.fromhex("820102"))
                self.assertEqual(len(result["segments"]), 1)

    def test_extra_spaces_do_not_turn_plain_hex_into_an_address(self):
        for source, expected in [("8201  02", "820102"), ("82010203  04050607", "8201020304050607")]:
            with self.subTest(source=source):
                self.assertEqual(self.parsed(source)["data"], bytes.fromhex(expected))

    def test_xxd_ascii_column_can_itself_look_like_hex(self):
        for ascii_column in ["AB", "CD"]:
            with self.subTest(ascii_column=ascii_column):
                source = "00000000: 4142  " + ascii_column
                self.assertEqual(self.parsed(source)["data"], b"AB")

    def test_log_prefixes_do_not_become_hex(self):
        for source in [
            "Data: 82 01 02",
            "2026-11-19 13:00:00 RX: 82 01 02",
            "[2026-11-19 13:00:00] INFO RX: 82 01 02",
        ]:
            with self.subTest(source=source):
                self.assertEqual(self.parsed(source)["data"], bytes.fromhex("820102"))

    def test_base64_and_missing_padding(self):
        for source, expected in [("ggEC", "820102"), ("GCo=", "182a"), ("GCo", "182a")]:
            with self.subTest(source=source):
                result = self.parsed(source)
                self.assertEqual(result["data"], bytes.fromhex(expected))
                self.assertEqual(result["format"], "base64")
        self.assertEqual(self.parsed("g g\nE C", "base64")["data"], bytes.fromhex("820102"))

    def test_base64_url_and_data_uri(self):
        raw = bytes.fromhex("43fffefd")
        for source in [
            base64.urlsafe_b64encode(raw).decode(),
            base64.urlsafe_b64encode(raw).decode().rstrip("="),
            "data:application/cbor;base64," + base64.b64encode(raw).decode(),
        ]:
            with self.subTest(source=source):
                self.assertEqual(self.parsed(source)["data"], raw)

    def test_json_syntax_wins_over_accidental_cbor_hits(self):
        source = '{"a":1,"payload":"820102","$bytes":"ffff","nested":[1,2,3]}'
        result = self.parsed(source)
        self.assertEqual(result["format"], "json")
        self.assertEqual(result["data"], decode_input(source, "json"))

    def test_explicit_json_array_preserves_array_type(self):
        result = self.parsed("[130, 1, 2]", "json")
        self.assertEqual(result["format"], "json")
        self.assertEqual(result["data"], decode_input("[130, 1, 2]", "json"))
        self.assertNotEqual(result["data"], bytes.fromhex("820102"))

    def test_diagnostic_bytes_and_tags_preserve_meaning(self):
        for source in ["h'820102'", "24(h'820102')", '[_ 1, {"b": h\'ff\'}]']:
            with self.subTest(source=source):
                result = self.parsed(source)
                self.assertEqual(result["format"], "diagnostic")
                self.assertEqual(result["data"], decode_input(source, "diagnostic"))

    def test_explicit_hex_keeps_existing_h_literal_behavior(self):
        self.assertEqual(self.parsed("h'820102'", "hex")["data"], bytes.fromhex("820102"))

    def test_incorrect_selected_format_falls_back(self):
        for source, preferred, detected, expected in [
            ('{"a":1}', "hex", "json", bytes.fromhex("a1616101")),
            ('{"a":1}', "base64", "json", bytes.fromhex("a1616101")),
            ("82 01 02", "json", "hex", bytes.fromhex("820102")),
            ("ggEC", "hex", "base64", bytes.fromhex("820102")),
        ]:
            with self.subTest(preferred=preferred, source=source):
                result = self.parsed(source, preferred)
                self.assertEqual(result["data"], expected)
                self.assertEqual(result["format"], detected)

    def test_unknown_text_preserves_utf8_bytes(self):
        for source in ["not CBOR — 日本語", "未対応の形式です。", "🛰️\u0000日本語"]:
            with self.subTest(source=source):
                result = self.parsed(source)
                self.assertEqual(result["format"], "text")
                self.assertEqual(result["data"], source.encode("utf-8"))

    def test_explicit_text_and_binary_preserve_transport(self):
        source = '{"a":1}'
        self.assertEqual(self.parsed(source, "text")["data"], source.encode("utf-8"))
        raw = bytes(range(256))
        self.assertEqual(self.parsed(raw.hex(), "binary")["data"], raw)

    def test_unknown_tokens_create_boundaries(self):
        result = self.parsed("82 01 ZZ 02")
        self.assertEqual(result["data"], bytes.fromhex("820102"))
        self.assertEqual([(s["start"], s["end"]) for s in result["segments"]], [(0, 2), (2, 3)])
        self.assertTrue(result["warnings"])

    def test_dump_address_gaps_create_boundaries(self):
        result = self.parsed("00000000: 82 01\n00000004: 02")
        self.assertEqual(result["data"], bytes.fromhex("820102"))
        self.assertEqual([(s["start"], s["end"]) for s in result["segments"]], [(0, 2), (2, 3)])
        self.assertTrue(result["warnings"])

    def test_odd_hex_nibble_is_reported_without_padding(self):
        for source in ["82010", "82 01 0"]:
            with self.subTest(source=source):
                result = self.parsed(source, "hex")
                self.assertEqual(result["data"], bytes.fromhex("8201"))
                self.assertTrue(result["warnings"])

    def test_no_cbor_match_does_not_reject_input(self):
        result = self.parsed("ff ff ff")
        self.assertEqual(result["data"], b"\xff\xff\xff")

    def test_malformed_notation_is_retained_instead_of_rejected(self):
        for source in ["{", "[1,", "@@@", "zz", "0x", "82 01 ?? 02"]:
            for preferred in ["auto", "hex", "base64", "json", "diagnostic"]:
                with self.subTest(source=source, preferred=preferred):
                    # Recovery may extract a valid region or retain the original
                    # UTF-8. Either way, a nonempty input remains inspectable.
                    self.assertTrue(self.parsed(source, preferred)["data"])

    def test_empty_input_remains_an_explicit_input_error(self):
        with self.assertRaises(CBORError):
            parse_input("")

    def test_invalid_format_value_is_a_controlled_input_error(self):
        for preferred in [[], {}]:
            with self.subTest(preferred=preferred):
                with self.assertRaises(CBORError):
                    parse_input("820102", preferred)


if __name__ == "__main__":
    unittest.main()
