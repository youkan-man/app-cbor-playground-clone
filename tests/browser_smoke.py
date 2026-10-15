"""Playwright interaction / screenshot tests.

Normal: python tests/browser_smoke.py --url http://localhost:8080
Restricted offline environment: --in-process serves the real app's API through
an ASGI TestClient binding, and injects the unchanged HTML/CSS/JS. This mode tests
DOM behavior, NOT browser networking, CSP, Docker or a reverse proxy.
Use a fresh disposable instance; the tests create their own history.
"""
import argparse
import asyncio
import json
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from playwright.async_api import async_playwright


async def run(args):
    with tempfile.TemporaryDirectory() as data:
        async with async_playwright() as pw:
            browser=await pw.chromium.launch(executable_path=args.chromium or None,headless=True,args=['--no-sandbox'])
            page=await browser.new_page(viewport={'width':1440,'height':960},device_scale_factor=1)
            errors=[]
            page.on('pageerror',lambda e:errors.append(str(e)))
            if args.in_process:
                from starlette.testclient import TestClient
                from app import create_app
                client=TestClient(create_app(data))
                async def api_call(path,options):
                    r=client.request(options.get('method','GET'),path,content=options.get('body'),headers=options.get('headers',{}))
                    return {'status':r.status_code,'body':r.text,'headers':dict(r.headers)}
                await page.expose_function('__test_request',api_call)
                html=client.get('/').text
                html=re.sub(r'<script\b[^>]*>.*?</script>','',html,flags=re.S)
                html=re.sub(r'<link\b[^>]*>','',html)
                await page.set_content(html)
                await page.add_style_tag(content=(ROOT/'static/style.css').read_text())
                await page.evaluate("""() => {
                    window.fetch = async (path, options={}) => {
                        const r=await window.__test_request(String(path),options);
                        return new Response(r.status===204?null:r.body,{status:r.status,headers:r.headers});
                    };
                }""")
                await page.add_script_tag(content=(ROOT/'static/app.js').read_text(),type='module')
            else:
                await page.goto(args.url)
            await page.wait_for_function("document.querySelector('#serverState').textContent.includes('接続済み')")
            await page.evaluate("""() => {
                Object.defineProperty(navigator,'clipboard',{configurable:true,value:{
                    writeText:async text => {window.__lastCopy=text;},
                    readText:async () => '820102'
                }});
            }""")
            # Frame prefix: examine every byte and find the map at offset 4.
            await page.locator('#newButton').click()
            await page.locator('#sampleButton').click()
            await page.get_by_role('menuitem',name='ヘッダー + CBOR + ノイズ · HEX').click()
            await page.locator('#analysisTitle').fill('Frame A / telemetry')
            await page.locator('#analyzeButton').click()
            await page.wait_for_function("document.querySelector('#metricOffset').textContent==='0x0004'")
            assert await page.locator('#metricHits').inner_text()=='23'
            await page.wait_for_function("document.querySelectorAll('.history-item').length===1")
            first=await page.locator('.history-item').get_attribute('data-history')
            # Tree -> byte linkage, copy menu returns only hexadecimal.
            await page.locator('.tree-row[data-node="0"]').click()
            assert '118 B' in await page.locator('#selectionInfo').inner_text()
            await page.locator('[data-byte="4"]').click(button='right')
            await page.get_by_role('menuitem',name='HEX のみコピー',exact=True).click()
            copied=await page.evaluate('window.__lastCopy')
            assert re.fullmatch(r'[0-9A-F]{2}( [0-9A-F]{2})*',copied),copied
            assert copied.startswith('A6 66') and len(copied.split())==118
            # Node context distinguishes display text from raw value.
            await page.locator('.tree-row[data-node="2"]').click(button='right')
            await page.get_by_role('menuitem',name='値をコピー',exact=True).click()
            await page.wait_for_function("window.__lastCopy==='sensor-01'")
            await page.locator('.tree-row[data-node="2"]').click(button='right')
            await page.get_by_role('menuitem',name='表示値をコピー',exact=True).click()
            await page.wait_for_function("window.__lastCopy==='\"sensor-01\"'")
            # Keyboard context menus.
            await page.locator('.history-item').focus()
            await page.keyboard.press('Shift+F10')
            assert await page.locator('#contextMenu').is_visible()
            await page.keyboard.press('Escape')
            # Named second result, compared against first.
            await page.locator('#sampleButton').click()
            await page.get_by_role('menuitem',name='テレメトリ · JSON → CBOR').click()
            text=await page.locator('#sourceInput').input_value()
            text=text.replace('23.75','24.5').replace('"seq": 42','"seq": 43').replace('"current": 0.125','"current": 0.14')
            await page.locator('#sourceInput').fill(text)
            await page.locator('#analysisTitle').fill('Frame B / telemetry')
            await page.locator('#analyzeButton').click()
            await page.wait_for_function("document.querySelectorAll('.history-item').length===2")
            second=await page.locator('.history-item.active').get_attribute('data-history')
            await page.locator(f'[data-check="{first}"]').check()
            await page.locator(f'[data-check="{second}"]').check()
            await page.locator('#compareButton').click()
            await page.wait_for_function("!document.querySelector('#compareDock').hidden")
            assert '3 変更' in await page.locator('#compareStats').inner_text()
            assert await page.locator('.compare-row.changed').count()==3
            # Actual UI evidence, not generated design art.
            out=Path(args.output);out.mkdir(parents=True,exist_ok=True)
            await page.evaluate("document.querySelector('#toast').hidden=true")
            await page.screenshot(path=str(out/'cbor-workbench-comparison.png'),full_page=True)
            await page.locator('#compareMode').select_option('decoded-bytes')
            assert await page.locator('.compare-row').count()>0
            await page.locator('#compareMode').select_option('bytes')
            assert await page.locator('.compare-row').count()>0
            await page.locator('#compareMode').select_option('diagnostic')
            assert await page.locator('.compare-row').count()>0
            await page.locator('#compareMode').select_option('structure')
            await page.locator('#closeCompareButton').click()
            # Pane boundary drag.
            split=await page.locator('#mainSplitter').bounding_box()
            before=await page.locator('#sourceColumn').evaluate('(el)=>el.clientWidth')
            await page.mouse.move(split['x']+2,split['y']+80);await page.mouse.down()
            await page.mouse.move(split['x']+45,split['y']+80,steps=6);await page.mouse.up()
            after=await page.locator('#sourceColumn').evaluate('(el)=>el.clientWidth')
            assert after>before+30,(before,after)
            await page.locator('#mainSplitter').dblclick()
            # JSON and diagnostic views, candidate switching and exact mode.
            await page.get_by_role('tab',name='Diagnostic',exact=True).click()
            assert '24.5' in await page.locator('#textResult').inner_text()
            await page.get_by_role('tab',name='JSON',exact=True).click()
            assert json.loads(await page.locator('#textResult').inner_text())['seq']==43
            await page.get_by_role('tab',name='構造ツリー',exact=True).click()
            candidate=page.locator('.candidate-row').nth(1)
            offset=await candidate.get_attribute('data-candidate')
            await candidate.click()
            await page.wait_for_function('(n)=>parseInt(document.querySelector("#metricOffset").textContent,16)===n',arg=int(offset))
            await page.locator('.candidate-row').first.click()
            await page.wait_for_function("document.querySelector('#metricOffset').textContent==='0x0000'")
            # Invalid HEX has a clear error, no history added.
            await page.locator('#inputFormat').select_option('hex')
            await page.locator('#sourceInput').fill('xyz')
            await page.locator('#analyzeButton').click()
            await page.wait_for_function("document.querySelector('#statusMessage').classList.contains('error')")
            assert await page.locator('.history-item').count()==2
            await page.locator(f'[data-history="{first}"]').click()
            await page.wait_for_function("document.querySelector('#metricOffset').textContent==='0x0004'")
            await page.evaluate("document.querySelector('#toast').hidden=true")
            await page.screenshot(path=str(out/'cbor-workbench-desktop.png'),full_page=True)
            await page.locator('#themeButton').click()
            await page.screenshot(path=str(out/'cbor-workbench-light.png'),full_page=True)
            await page.locator('#themeButton').click()
            # Responsive layout stays within the document width.
            await page.set_viewport_size({'width':390,'height':844})
            await page.wait_for_timeout(100)
            assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth'), await page.evaluate('[document.documentElement.scrollWidth,innerWidth]')
            await page.screenshot(path=str(out/'cbor-workbench-mobile.png'),full_page=True)
            assert not errors,errors
            print('PASS: scan, tree↔bytes, contextual copy, Shift+F10, history, structural/byte/diagnostic comparison, resizing, views, candidate selection, error handling, dark/light/mobile.')
            print('Browser page errors:',errors)
            await browser.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--url',default='http://localhost:8080')
    parser.add_argument('--chromium',default='')
    parser.add_argument('--output',default='artifacts')
    parser.add_argument('--in-process',action='store_true')
    asyncio.run(run(parser.parse_args()))
