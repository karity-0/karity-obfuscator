"""Optional Playwright smoke test; pass a PNG path to retain a v2 screenshot."""
from __future__ import annotations

import copy
import os
from pathlib import Path
import sys
import tempfile

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from playwright.sync_api import sync_playwright

from obfuscator_gui import Api, _normalize_preferences


def check_editor_scrollbars(page):
    for selector in ['#input-script', '#output-script']:
        editor = page.locator(selector)
        original = editor.input_value()
        editor.evaluate(r'''el => {
            el.value=Array.from({length:200},(_,i)=>'local value'+i+' = "'+ 'scroll '.repeat(100)+'"').join('\n');
            el.dispatchEvent(new Event('input',{bubbles:true}));el.scrollTop=0;el.scrollLeft=0;
        }''')
        surface = editor.locator('..')
        vertical = surface.locator('.editor-scrollbar.vertical')
        horizontal = surface.locator('.editor-scrollbar.horizontal')
        page.wait_for_function('selector=>document.querySelector(selector).parentElement.querySelector(".vertical").getAttribute("aria-disabled")==="false"', arg=selector)
        assert vertical.is_visible() and horizontal.is_visible()
        for bar, axis in [(vertical, 'scrollTop'), (horizontal, 'scrollLeft')]:
            track = bar.bounding_box()
            thumb = bar.locator('.editor-scrollbar-thumb').bounding_box()
            page.mouse.move(thumb['x'] + thumb['width']/2, thumb['y'] + thumb['height']/2)
            page.mouse.down()
            page.mouse.move(track['x'] + track['width']*.7, track['y'] + track['height']*.7, steps=8)
            page.mouse.up()
            page.wait_for_function('args=>document.querySelector(args[0])[args[1]]>100', arg=[selector, axis])
        page.wait_for_function('selector=>Number(document.querySelector(selector).parentElement.querySelector(".line-gutter span").textContent)>50', arg=selector)
        assert surface.locator('.highlight-layer span').count() < 500
        vertical.focus()
        page.keyboard.press('Home')
        page.wait_for_function('selector=>document.querySelector(selector).scrollTop===0', arg=selector)
        page.keyboard.press('End')
        page.wait_for_function('selector=>{const el=document.querySelector(selector);return el.scrollTop>=el.scrollHeight-el.clientHeight-1}', arg=selector)
        vertical.hover()
        page.mouse.wheel(0, -120)
        page.wait_for_function('selector=>{const el=document.querySelector(selector);return el.scrollTop<el.scrollHeight-el.clientHeight-50}', arg=selector)
        editor.evaluate('''(el,value)=>{el.value=value;el.dispatchEvent(new Event('input',{bubbles:true}));el.scrollTop=0;el.scrollLeft=0;}''', original)


def main() -> int:
    api = Api()
    bootstrap = api.get_bootstrap()
    bootstrap["preferences"] = _normalize_preferences({"theme": "dark"})
    saved = []
    errors = []
    with tempfile.TemporaryDirectory(prefix="karity-gui-web-") as temp, sync_playwright() as p:
        browser = p.chromium.launch(headless=True, env={**os.environ, "CHROME_LOG_FILE": str(Path(temp) / "chromium.log")})
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.expose_function("bootstrapGui", lambda: copy.deepcopy(bootstrap))
        page.expose_function("persistPreferences", lambda value: saved.append(value) or {
            "ok": True, "preferences": _normalize_preferences(value),
        })
        page.expose_function("buildGui", api.run_obfuscation)
        page.expose_function("startLua", api.start_execution)
        page.expose_function("pollLua", api.poll_execution)
        page.expose_function("inputLua", api.send_execution_input)
        page.expose_function("stopLua", api.stop_execution)
        page.add_init_script("""
          window.pywebview = {api: {
            get_bootstrap: () => window.bootstrapGui(), get_version: async () => 'test',
            save_preferences: value => window.persistPreferences(value),
            run_obfuscation: value => window.buildGui(value),
            start_execution: value => window.startLua(value),
            poll_execution: (id, cursor) => window.pollLua(id, cursor),
            send_execution_input: (id, value) => window.inputLua(id, value),
            stop_execution: id => window.stopLua(id),
          }};
        """)
        page.goto((ROOT_DIR / "gui/web/index.html").as_uri())
        page.wait_for_function("document.querySelector('#backend-label').textContent === 'backend ready'")
        assert page.locator(".quick-setup").is_visible()
        assert not page.locator("#preset-select").is_visible()
        assert page.locator("#run-btn").inner_text().startswith("난독화")
        page.locator('[data-preset="fast-vm"]').click()
        assert page.locator('[data-preset="fast-vm"]').get_attribute("aria-pressed") == "true"
        page.locator("#input-script").fill('print("marker")')
        page.locator("#input-script").evaluate("el => el.setSelectionRange(6, 14)")
        page.locator("#marker-tools > summary").click()
        page.locator("#insert-marker-btn").click()
        assert page.locator("#input-script").input_value() == 'print(STRING_OBF("marker"))'
        page.wait_for_function("document.querySelector('.token-marker')?.textContent === 'STRING_OBF'")
        page.locator('#execute-source-btn').click()
        page.wait_for_function("document.querySelector('#execution-stop').disabled")
        assert page.locator('#console-output').inner_text().strip() == 'marker'
        page.locator('#input-script').fill('error("intentional failure <img>")')
        page.locator('#execute-source-btn').click()
        page.wait_for_function("document.querySelector('#execution-stop').disabled")
        assert '실행 실패' in page.locator('#execution-status').inner_text()
        assert 'intentional failure <img>' in page.locator('#console-output').inner_text()
        assert page.locator('#console-output img').count() == 0
        page.locator('#input-script').fill('io.write("name? "); print(io.read())')
        page.keyboard.press('F5')
        page.wait_for_function("document.querySelector('#console-output').textContent.includes('name?')")
        page.locator('#preferences-btn').click()
        page.locator('#general-tab').click()
        page.locator('#language-select').select_option('en')
        assert 'Source' in page.locator('#execution-status').inner_text()
        assert 'Running' in page.locator('#execution-status').inner_text()
        page.locator('#language-select').select_option('ko')
        page.locator('#preferences-close').click()
        if len(sys.argv) > 1:
            page.screenshot(path=str(Path(sys.argv[1]).with_stem('gui-execution-console')))
        page.locator('#console-input').fill('hello')
        page.locator('#console-input').press('Enter')
        page.wait_for_function("document.querySelector('#execution-stop').disabled")
        assert 'hello' in page.locator('#console-output').inner_text()
        page.locator('#input-script').fill('while true do end')
        page.locator('#execute-source-btn').click()
        page.locator('#execution-stop').click()
        page.wait_for_function("document.querySelector('#execution-stop').disabled")
        assert '중지됨' in page.locator('#execution-status').inner_text()
        page.locator('#console-hide').click()
        page.locator('#input-script').fill('print(STRING_OBF("marker"))')

        # Switching designs preserves code, build controls, and output.
        page.locator("#output-script").evaluate("el => el.value = 'keep output'")
        page.locator("#preferences-btn").click()
        page.locator("#gui-tab").click()
        page.locator('[data-gui-choice="v1"]').click()
        assert page.locator("html").get_attribute("data-gui-version") == "v1"
        page.locator("#preferences-close").click()
        assert page.locator("#preset-select").is_visible()
        assert page.locator("#preset-select").input_value() == "fast-vm"
        assert not page.locator(".quick-setup").is_visible()
        assert page.locator("#input-script").input_value() == 'print(STRING_OBF("marker"))'
        assert page.locator("#output-script").input_value() == "keep output"
        check_editor_scrollbars(page)

        # Region insertion respects a selection that ends at the next line start.
        source = 'local x = 1\nprint(x)\nprint("tail")\n'
        page.locator("#input-script").fill(source)
        page.locator("#input-script").evaluate("el => el.setSelectionRange(0, 21)")
        page.locator("#marker-tools > summary").click()
        page.locator("#marker-kind").select_option("VM_START")
        page.locator("#marker-options").fill('profile="fast-vm", junk_rate=0.05')
        page.locator("#insert-marker-btn").click()
        expected = '-- @VM_START(profile="fast-vm", junk_rate=0.05)\nlocal x = 1\nprint(x)\n-- @VM_END\nprint("tail")\n'
        assert page.locator("#input-script").input_value() == expected
        page.locator("#run-btn").click()
        page.wait_for_function("!document.querySelector('#run-btn').disabled", timeout=300000)
        assert page.locator("#status-msg").get_attribute("data-message").startswith("Protection complete"), page.locator("#output-script").input_value()
        page.keyboard.press('Shift+F5')
        page.wait_for_function("document.querySelector('#execution-stop').disabled")
        assert page.locator('#console-output').inner_text().replace('\r', '').strip() == '1\ntail'
        page.locator('#console-hide').click()

        page.locator("#preferences-btn").click()
        page.locator('[data-gui-choice="v2"]').click()
        page.locator("#preferences-close").click()
        assert not page.locator("#preset-select").is_visible()
        page.locator("#split-view").click()
        check_editor_scrollbars(page)
        for width, height in [(1440, 900), (1040, 680)]:
            page.set_viewport_size({"width": width, "height": height})
            page.locator('#console-toggle').click()
            for selector in ["#run-btn", "#input-script", "#output-script", "#marker-tools"]:
                box = page.locator(selector).bounding_box()
                assert box and box["x"] >= 0 and box["y"] >= 0
                assert box["x"] + box["width"] <= width and box["y"] + box["height"] <= height
                assert box['height'] > (35 if selector.endswith('-script') else 20)
            page.locator('#console-hide').click()
        page.locator("#settings-open").click()
        assert page.locator("#preset-select").is_visible()
        page.locator("#settings-close").click()
        page.locator("#source-view").click()
        # All palettes are selectable; previews and the application share values.
        page.locator("#preferences-btn").click()
        page.locator("#appearance-tab").click()
        assert page.locator(".theme-tile").count() == len(bootstrap["themes"])
        for key, theme in bootstrap["themes"].items():
            page.locator(f'[data-theme-choice="{key}"]').click()
            assert page.locator(f'[data-theme-choice="{key}"]').get_attribute("aria-pressed") == "true"
            if key != "system":
                actual = page.locator("html").evaluate("el => el.style.getPropertyValue('--bg')")
                assert actual == theme["background"]
        page.locator("#general-tab").click()
        page.locator("#language-select").select_option("en")
        assert page.locator("#run-btn").inner_text().startswith("Obfuscate")
        assert page.locator("#editor-tab").inner_text() == "Editor"
        assert page.locator("html").get_attribute("lang") == "en"
        assert page.locator("#input-script").input_value() == expected
        page.locator("#language-select").select_option("ko")
        page.locator("#editor-tab").click()
        page.locator("#editor-font-size").fill("16")
        page.locator("#editor-font-size").dispatch_event("input")
        page.locator("#appearance-tab").click()
        page.locator('[data-theme-choice="crystal"]').click()
        if len(sys.argv) > 1:
            page.screenshot(path=str(Path(sys.argv[1]).with_stem("preferences-themes")))
        page.locator("#preferences-close").click()
        example = '-- @VM_START\nlocal function greet(name)\n  local message = STRING_OBF("hello, " .. name)\n  return message, 42\nend\n-- @VM_END\n'
        page.locator("#input-script").fill(example)
        page.wait_for_function("document.querySelector('.token-keyword')?.textContent === 'local'")
        assert page.locator('.code-surface .token-comment').count() >= 2
        assert page.locator('.code-surface .token-string').count() >= 1
        assert page.locator('.code-surface .token-number').count() >= 1
        # HTML-like source remains text, and long comments retain Lua semantics.
        page.locator("#input-script").fill('local text = "<img src=x>"\n--[=[ local ignored = 99 ]=]\nreturn text')
        page.wait_for_function("document.querySelector('.code-surface .token-string')?.textContent.includes('<img')")
        assert page.locator('.highlight-layer img').count() == 0
        assert page.locator('.editor-card:not(.output-card) .token-comment').inner_text() == '--[=[ local ignored = 99 ]=]'
        # Rendering stays bounded while moving through a large script.
        page.locator("#input-script").evaluate("""el => {
          el.value = 'local n = 42; print("hello")\\n'.repeat(20000);
          el.dispatchEvent(new Event('input', {bubbles: true}));
          el.scrollTop = el.scrollHeight - el.clientHeight;
          el.dispatchEvent(new Event('scroll'));
        }""")
        page.wait_for_function("Number(document.querySelector('.editor-card:not(.output-card) .line-gutter span')?.textContent) > 19000")
        assert page.locator('.editor-card:not(.output-card) .highlight-layer span').count() < 250
        page.locator("#input-script").evaluate("""el => {
          el.value = 'local n=42;'.repeat(50000);
          el.dispatchEvent(new Event('input', {bubbles: true}));
          el.scrollLeft = 100000;
          el.dispatchEvent(new Event('scroll'));
        }""")
        page.wait_for_function("document.querySelector('#input-script').scrollLeft > 1000")
        assert page.locator('.editor-card:not(.output-card) .highlight-layer span').count() < 250
        page.locator("#input-script").fill(example.replace('"hello, " .. name', '"hello, karity"'))
        page.set_viewport_size({"width": 1440, "height": 900})
        screenshot_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(temp) / "v2.png"
        page.screenshot(path=str(screenshot_path))
        # Wait on a meaningful saved condition, without touching real preferences.
        page.wait_for_function("document.querySelector('#preferences-status').textContent === '저장됨'")
        assert saved[-1]["gui_version"] == "v2"
        assert saved[-1]["theme"] == "crystal" and saved[-1]["language"] == "ko"
        assert not errors, errors
        browser.close()
    api._execution.close()
    print("gui-web-regression-ok: execution, console, presets, markers, builds, v1/v2, preferences, layout")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
