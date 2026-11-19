"""Real browser/HTTP checks for auto input and file-byte preservation.

Run against a disposable instance; this creates history records.
python tests/browser_auto_input.py --url http://localhost:8080 --chromium /usr/bin/chromium
"""
import argparse
from pathlib import Path

from playwright.sync_api import expect, sync_playwright


def run(args):
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    checks, errors = [], []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=args.chromium, headless=True,
                                     args=["--no-sandbox"])
        page = browser.new_page(viewport={"width": 1440, "height": 960})
        page.set_default_timeout(10000)
        page.on("pageerror", lambda error: errors.append(str(error)))
        try:
            page.goto(args.url)
            expect(page.locator("#serverState")).to_contain_text("接続済み")
            page.locator("#newButton").click()
            assert page.locator("#inputFormat").input_value() == "auto"

            def submit():
                with page.expect_response(lambda response: response.url.endswith("/api/analyze")) as received:
                    page.locator("#analyzeButton").click()
                response = received.value
                assert response.status == 201, response.text()
                record = response.json()
                page.locator(f'.history-item.active[data-history="{record["id"]}"]').wait_for()
                return record

            def analyze(source, fmt="auto", title="入力確認"):
                page.locator("#inputFormat").select_option(fmt)
                page.locator("#sourceInput").fill(source)
                page.locator("#analysisTitle").fill(title)
                return submit()

            for source in ["820102", "0x82, 0x01, 0x02", r"\x82\x01\x02", "ggEC",
                           "00000000: 82 01 02  |...|", "2026-11-19 13:00:00 RX: 82 01 02"]:
                record = analyze(source)
                assert record["hex"] == "820102", (source, record["hex"])
                assert record["result"]["selected"]["json"] == [[1, 2]]
                assert page.locator("#sourceInput").input_value() == source
            checks.append("Six input syntaxes parse without changing the format selector")

            record = analyze('{"a":1}', "hex")
            assert record["result"]["input"]["format"] == "json"
            assert "JSON" in page.locator("#inputInfo").inner_text()
            assert "JSON" in page.locator(".history-item.active").inner_text()
            checks.append("A stale HEX selection accepts JSON and displays the detected format")

            source = "82 01 ZZ 83 01 02 03"
            damaged = analyze(source, title="途中に欠損があるログ")
            assert damaged["result"]["selected"]["offset"] == 2
            assert len(damaged["result"]["input"]["segments"]) == 2
            assert page.locator(".hex-byte.segment-start").count() == 1
            assert "分断" in page.locator("#inputInfo").inner_text()
            page.locator("#inputMenuButton").click()
            page.get_by_role("menuitem", name="HEX を整形（16 B / 行）").click()
            expect(page.locator("#statusMessage")).to_contain_text("元の入力を保持")
            assert page.locator("#sourceInput").input_value() == source
            page.locator("#hexView").click(button="right")
            page.get_by_role("menuitem", name="すべて選択").click()
            page.locator("#hexView").click(button="right")
            with page.expect_response(lambda response: response.url.endswith("/api/analyze")) as extracted:
                page.get_by_role("menuitem", name="選択範囲を新しく解析", exact=True).click()
            again = extracted.value.json()
            assert again["hex"] == damaged["hex"]
            assert len(again["result"]["input"]["segments"]) == 2
            assert again["result"]["selected"]["hits"] == 4
            page.locator(f'.history-item.active[data-history="{again["id"]}"]').wait_for()
            checks.append("Gap markers, safe formatting and contextual reanalysis preserve fragment boundaries")

            for name, raw, expected, detected in [
                ("capture.txt", bytes.fromhex("ff820102"), "ff820102", "binary"),
                ("capture.cbor", b"AB", "4142", "binary"),
                ("message.unknown", b'{"a":1}', "a1616101", "json"),
                ("utf16-le.log", b"\xff\xfe" + "82 01 02".encode("utf-16le"), "820102", "hex"),
                ("utf16-be.log", b"\xfe\xff" + "82 01 02".encode("utf-16be"), "820102", "hex"),
                ("all-bytes.hex", bytes(range(256)), bytes(range(256)).hex(), "binary"),
            ]:
                page.locator("#fileInput").set_input_files({"name": name, "mimeType": "application/octet-stream", "buffer": raw})
                expect(page.locator("#analysisTitle")).to_have_value(name)
                file_record = submit()
                assert file_record["hex"] == expected, (name, file_record["hex"])
                assert file_record["result"]["input"]["format"] == detected, (name, file_record["result"]["input"])
            checks.append("Binary, unknown extensions and both UTF-16 byte orders retain correct data")

            record = analyze("ff ff ff", title="一致なしも保存")
            assert record["result"]["selected"]["hits"] == 0
            assert page.locator("#emptyResult").is_visible()
            assert page.locator("#emptySampleButton").is_hidden()
            page.locator("#toast").wait_for(state="hidden")
            page.screenshot(path=str(output / "no-match.png"))
            checks.append("No-match input remains visible and is saved to history")

            text = "未対応の形式です。"
            record = analyze(text, title="形式不明の入力")
            assert record["hex"] == text.encode().hex()
            assert record["result"]["input"]["format"] == "text"
            page.reload()
            expect(page.locator("#serverState")).to_contain_text("接続済み")
            page.locator(f'.history-item[data-history="{record["id"]}"]').click()
            expect(page.locator("#sourceInput")).to_have_value(text)
            assert "UTF-8" in page.locator("#inputInfo").inner_text()
            checks.append("Unknown input keeps its source, byte representation and detected format after reload")

            # Leave realistic recovered input visible for visual regression inspection.
            source = "2026-11-19 13:00:00 RX: FF FF A2 66 73 65 6E 73 6F 72 67 73 65 6E 73 6F 72 31 65 76 61 6C 75 65 18 2A FF"
            final = analyze(source, title="受信ログ / 自動判定")
            assert final["result"]["selected"]["json"] == [{"sensor": "sensor1", "value": 42}]
            page.locator("#toast").wait_for(state="hidden")
            page.screenshot(path=str(output / "auto-input-desktop.png"))
            for width, height in [(1366, 768), (390, 844)]:
                page.set_viewport_size({"width": width, "height": height})
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
                page.screenshot(path=str(output / f"auto-input-{width}.png"), full_page=True)
            checks.append("Desktop and mobile layouts remain within the viewport")
            assert not errors, errors
            for check in checks:
                print("PASS:", check, flush=True)
            print(f"{len(checks)} browser checks passed; no uncaught JavaScript errors", flush=True)
        except Exception:
            page.screenshot(path=str(output / "failure.png"), full_page=True)
            raise
        finally:
            browser.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://localhost:8080")
    parser.add_argument("--chromium", default=None)
    parser.add_argument("--output", default="test-evidence/auto-input")
    run(parser.parse_args())
