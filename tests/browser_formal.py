"""Formal-light UI regressions against a DISPOSABLE test instance.

  python tests/browser_formal.py --url http://localhost:8080 --chromium /usr/bin/chromium
  python tests/browser_formal.py --in-process --chromium /usr/bin/chromium

Normal mode uses real browser HTTP. In-process mode injects the repository's
unchanged HTML/CSS/JS and connects fetch to the real ASGI app/TestClient. It
verifies DOM interactions and backend behavior, not browser networking, CSP,
Docker or a reverse proxy. Only in-process mode simulates localStorage because
about:blank has no persistent origin. Tests create history; never use production.
"""
from __future__ import annotations
import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def run(args: argparse.Namespace) -> None:
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    checks: list[str] = []
    errors: list[str] = []
    with tempfile.TemporaryDirectory() as directory, sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=args.chromium, headless=True, args=['--no-sandbox'])
        page = browser.new_page(viewport={'width': 1440, 'height': 960}, device_scale_factor=1)
        page.set_default_timeout(10000)
        page.on('pageerror', lambda error: errors.append(str(error)))
        client = None
        try:
            if args.in_process:
                from starlette.testclient import TestClient
                from app import create_app
                client = TestClient(create_app(directory))

                def request(path, options):
                    response = client.request(options.get('method', 'GET'), path,
                        content=options.get('body'), headers=options.get('headers', {}))
                    return {'status': response.status_code, 'body': response.text, 'headers': dict(response.headers)}

                page.expose_function('__test_request', request)
                html = re.sub(r'<script\b[^>]*>.*?</script>', '', client.get('/').text, flags=re.S)
                html = re.sub(r'<link\b[^>]*>', '', html)
                page.set_content(html)
                page.add_style_tag(content=(ROOT / 'static/style.css').read_text())
                page.evaluate("""() => {
                    // Explicit storage simulation, not an origin-persistence test.
                    const data = new Map([['cbor.theme','dark'],['cbor.--source-width','1300'],
                        ['cbor.draft','{"text":"820102","format":"hex","title":"retained"}']]);
                    Object.defineProperty(window,'localStorage',{configurable:true,value:{
                        getItem:k=>data.has(k)?data.get(k):null,setItem:(k,v)=>data.set(k,String(v)),
                        removeItem:k=>data.delete(k)}});
                    window.fetch = async (path,options={}) => {
                        const r=await window.__test_request(String(path),options);
                        return new Response(r.status===204?null:r.body,{status:r.status,headers:r.headers});
                    };
                }""")
                page.add_script_tag(content=(ROOT / 'static/chrome.js').read_text())
                page.add_script_tag(content=(ROOT / 'static/app.js').read_text(), type='module')
            else:
                page.goto(args.url)
            page.wait_for_function("document.querySelector('#serverState').textContent.includes('接続済み')")
            if args.in_process:
                assert page.evaluate("localStorage.getItem('cbor.theme')") == 'light'
                assert page.evaluate("localStorage.getItem('cbor.--source-width')") == ''
                assert 'retained' in page.evaluate("localStorage.getItem('cbor.draft')")
                checks.append('One-time light/layout migration preserves the draft (simulated storage)')
            assert page.locator('html').get_attribute('data-theme') == 'light'
            assert page.locator('#sourceInput').evaluate('(el)=>getComputedStyle(el).backgroundColor') == 'rgb(255, 255, 255)'
            checks.append('White input and light initial theme')
            page.evaluate("""() => Object.defineProperty(navigator,'clipboard',{configurable:true,value:{
                writeText:async text=>{window.__lastCopy=text;},readText:async ()=>'820102'}})""")
            page.locator('#newButton').click()
            page.locator('#sampleButton').click()
            page.get_by_role('menuitem', name='ヘッダー + CBOR + ノイズ · HEX').click()
            page.locator('#analysisTitle').fill('Telemetry A / 送信データ')
            page.locator('#inputMenuButton').click()
            page.get_by_role('menuitem', name='HEX を整形（16 B / 行）').click()
            assert re.fullmatch(r'[0-9A-F ]+(\n[0-9A-F ]+)*', page.locator('#sourceInput').input_value())
            page.locator('#analyzeButton').click()
            page.wait_for_function("document.querySelector('#metricOffset').textContent==='0x0004'")
            assert page.locator('#metricHits').inner_text() == '23'
            assert page.locator('#metricBytes').inner_text() == '118 B'
            page.wait_for_function("document.querySelectorAll('.history-item').length===1")
            first = page.locator('.history-item').get_attribute('data-history')
            checks.append('Explicit input menu, formatting, 124 one-byte offsets and best offset 4 / 23 hits')

            page.locator('.tree-row[data-node="0"]').click()
            assert '118 B' in page.locator('#selectionInfo').inner_text()
            page.locator('[data-byte="4"]').click(button='right')
            page.get_by_role('menuitem', name='HEX のみコピー', exact=True).click()
            copied = page.evaluate('window.__lastCopy')
            assert copied.startswith('A6 66') and len(copied.split()) == 118
            page.locator('.tree-row[data-node="2"]').click()
            page.locator('#nodeMenuButton').click()
            page.get_by_role('menuitem', name='値をコピー', exact=True).click()
            page.wait_for_function("window.__lastCopy==='sensor-01'")
            page.locator('.tree-row[data-node="2"]').click(button='right')
            page.get_by_role('menuitem', name='表示値をコピー', exact=True).click()
            page.wait_for_function("window.__lastCopy==='\"sensor-01\"'")
            values = page.locator('.tree-value').evaluate_all('(els)=>els.slice(0,8).map(e=>e.getBoundingClientRect().left)')
            assert max(values) - min(values) < 1, values
            checks.append('Aligned values; tree-byte selection; explicit and right-click raw/display/HEX copy')

            page.locator('#historyMenuButton').click()
            page.get_by_role('menuitem', name='履歴を固定', exact=True).click()
            page.wait_for_selector('.pin-mark')
            page.locator('.history-item').focus()
            page.keyboard.press('Shift+F10')
            assert page.locator('#contextMenu').is_visible()
            page.keyboard.press('Escape')
            assert page.locator('#contextMenu').is_hidden()
            checks.append('Explicit history menu, pinning and keyboard context menu')

            page.locator('#treeTab').focus()
            page.keyboard.press('ArrowRight')
            assert page.locator('#diagnosticTab').get_attribute('aria-selected') == 'true'
            assert page.locator('#resultBody').get_attribute('aria-labelledby') == 'diagnosticTab'
            page.keyboard.press('End')
            assert 'sensor-01' in page.locator('#textResult').inner_text()
            page.keyboard.press('Home')
            page.locator('#collapseButton').click()
            assert page.locator('.tree-row').count() == 1
            page.locator('#expandButton').click()
            page.locator('#treeSearch').fill('temperature')
            assert 'temperature' in page.locator('#treeView').inner_text()
            page.locator('#treeSearch').fill('')
            checks.append('Keyboard result tabs, expansion and tree search')
            page.locator('#toast').wait_for(state='hidden')
            page.screenshot(path=str(output / 'analysis.png'))

            # Save a genuinely different record and compare the stored results.
            page.locator('#sampleButton').click()
            page.get_by_role('menuitem', name='テレメトリ · JSON → CBOR').click()
            value = json.loads(page.locator('#sourceInput').input_value())
            value['seq'] = 43
            value['readings']['temperature'] = 24.5
            value['readings']['current'] = 0.14
            page.locator('#sourceInput').fill(json.dumps(value, ensure_ascii=False, indent=2))
            page.locator('#analysisTitle').fill('Telemetry B / 受信データ')
            page.locator('#analyzeButton').click()
            page.wait_for_function("document.querySelectorAll('.history-item').length===2")
            second = page.locator('.history-item.active').get_attribute('data-history')
            assert second != first
            page.locator(f'[data-check="{first}"]').check()
            page.locator(f'[data-check="{second}"]').check()
            page.locator('#compareButton').click()
            page.wait_for_selector('.compare-row.changed')
            assert page.locator('.compare-row.changed').count() == 3
            assert 'seq' in page.locator('#compareView').inner_text()
            checks.append('Separate persisted histories and three structure/value changes')
            page.locator('.tree-row[data-node="2"]').click()
            page.screenshot(path=str(output / 'comparison.png'))
            page.locator('#expandCompareButton').click()
            assert page.locator('#analysisGrid').is_hidden()
            assert page.locator('#compareView').bounding_box()['height'] > 500
            page.screenshot(path=str(output / 'comparison-expanded.png'))
            for mode in ['decoded-bytes', 'bytes', 'diagnostic', 'structure']:
                page.locator('#compareMode').select_option(mode)
                assert page.locator('.compare-row').count() > 0
            page.locator('#swapCompareButton').click()
            page.wait_for_function("document.querySelector('#compareLabels').children[1].textContent.includes('Telemetry B')")
            page.locator('#swapCompareButton').click()
            page.wait_for_function("document.querySelector('#compareLabels').children[1].textContent.includes('Telemetry A')")
            page.locator('#expandCompareButton').click()
            assert page.locator('#analysisGrid').is_visible()
            checks.append('Expanded comparison, all four modes, swapping and restoring the workspace')

            divider = page.locator('#mainSplitter').bounding_box()
            before = page.locator('#sourceColumn').bounding_box()['width']
            page.mouse.move(divider['x'] + 2, divider['y'] + 70)
            page.mouse.down()
            page.mouse.move(divider['x'] + 75, divider['y'] + 70, steps=5)
            page.mouse.up()
            assert page.locator('#sourceColumn').bounding_box()['width'] > before + 50
            page.locator('#resetLayoutButton').click()
            assert abs(page.locator('#sourceColumn').bounding_box()['width'] - before) < 2
            checks.append('Drag resizing and one-click layout reset')

            page.locator('#themeButton').click()
            assert page.locator('html').get_attribute('data-theme') == 'dark'
            page.locator('#themeButton').click()
            assert page.locator('html').get_attribute('data-theme') == 'light'
            checks.append('Optional dark theme and return to light')
            for width, height in [(1920, 1080), (1440, 960), (1366, 768), (1024, 768), (768, 1024), (390, 844)]:
                page.set_viewport_size({'width': width, 'height': height})
                page.wait_for_timeout(80)
                assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1'), width
                if width > 980:
                    for target in ['#analyzeButton', '#inputMenuButton', '#compareMode', '#closeCompareButton']:
                        box = page.locator(target).bounding_box()
                        assert box['width'] > 0 and 0 <= box['x'] and box['x'] + box['width'] <= width+1, (width, target, box)
                if width == 390:
                    page.locator('#compareView').evaluate('(el)=>{el.scrollLeft=100;}')
                    page.wait_for_timeout(80)
                    delta = page.evaluate("document.querySelector('#compareView').scrollLeft-document.querySelector('#compareLabels').scrollLeft")
                    assert abs(delta) < 1, delta
                    page.locator('#hexView').evaluate('(el)=>{el.scrollLeft=100;}')
                    page.wait_for_timeout(80)
                    delta = page.evaluate("document.querySelector('#hexView').scrollLeft-document.querySelector('.hex-labels').scrollLeft")
                    assert abs(delta) < 1, delta
                    page.locator('#hexView').evaluate('(el)=>{el.scrollLeft=0;}')
                    page.locator('#compareView').evaluate('(el)=>{el.scrollLeft=0;}')
                    page.locator('#historyToggle').click()
                    assert page.locator('#historyToggle').get_attribute('aria-expanded') == 'true'
                    page.keyboard.press('Escape')
                    assert page.locator('#historyToggle').get_attribute('aria-expanded') == 'false'
                    page.screenshot(path=str(output / 'mobile.png'), full_page=True)
                if width == 1366:
                    page.screenshot(path=str(output / 'laptop.png'))
            checks.append('No page-width overflow at six viewports; visible desktop actions and mobile history drawer')

            page.set_viewport_size({'width': 1440, 'height': 960})
            page.locator('#expandCompareButton').click()
            page.locator('#newButton').click()
            assert page.locator('#analysisGrid').is_visible()
            page.locator('#closeCompareButton').click()
            page.locator('#sourceInput').fill('zz')
            page.locator('#analyzeButton').click()
            page.wait_for_function("document.querySelector('#statusMessage').classList.contains('error')")
            assert page.locator('#analyzeButton').is_enabled()
            page.locator('#inputFormat').select_option('base64')
            page.locator('#sourceInput').fill('ggEC')
            page.locator('#analyzeButton').click()
            page.wait_for_function("document.querySelector('#metricHits').textContent==='3'")
            page.locator('#sampleButton').click()
            page.get_by_role('menuitem', name='CBOR Sequence · 連続した3項目').click()
            page.keyboard.press('Control+Enter')
            page.wait_for_function("document.querySelector('#metricItems').textContent==='3'")
            checks.append('New analysis restores input; invalid-input recovery; Base64 and Diagnostic sequence keyboard analysis')
            assert not errors, errors
            checks.append('No uncaught browser JavaScript errors')
        except Exception:
            page.screenshot(path=str(output / 'failure.png'), full_page=True)
            raise
        finally:
            (output / 'results.json').write_text(json.dumps({'mode': 'in-process' if args.in_process else 'browser-http',
                'passed': checks, 'page_errors': errors}, ensure_ascii=False, indent=2))
            for check in checks:
                print('PASS:', check, flush=True)
            if client:
                client.close()
            browser.close()
    print(f'{len(checks)} checks passed', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', default='http://localhost:8080')
    parser.add_argument('--chromium', default=None)
    parser.add_argument('--in-process', action='store_true')
    parser.add_argument('--output', default='test-evidence/formal-ui')
    run(parser.parse_args())
