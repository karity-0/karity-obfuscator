/* Optional real-browser checks. Uses the real Python bridge; no fake progress. */
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const {spawn} = require('node:child_process');
const {createInterface} = require('node:readline');
const {chromium} = require('playwright');
const root = path.resolve(__dirname, '..');
const shots = path.resolve(process.argv[2] || path.join(root, 'temp-gui-experience'));
fs.mkdirSync(shots, {recursive:true});

(async () => {
  const server = spawn(process.env.KARITY_PYTHON || 'python', [path.join(__dirname,'gui_web_server.py')],
    {cwd:root, windowsHide:true, stdio:['ignore','pipe','inherit']});
  const url = await new Promise((resolve,reject) => {
    createInterface({input:server.stdout}).once('line', resolve);
    server.once('error',reject); server.once('exit',code=>reject(new Error(`Bridge exited ${code}`)));
  });
  const call = async (method,...args) => (await fetch(url+'/api',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({method,args})})).json();
  let browser;
  const errors=[];
  try {
    browser=await chromium.launch({headless:true, ...(process.env.KARITY_TEST_BROWSER ? {executablePath:process.env.KARITY_TEST_BROWSER} : {})});
    const page=await browser.newPage({viewport:{width:1440,height:900}});
    page.on('pageerror',error=>errors.push(error.message));
    await page.addInitScript(() => {
      const call=(method,...args)=>fetch('/api',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({method,args})}).then(r=>r.json());
      window.pywebview={api:new Proxy({}, {get:(_,method)=>(...args)=>call(method,...args)})};
    });
    await page.goto(url+'/index.html');
    await page.waitForFunction(()=>document.querySelector('#backend-label').textContent==='backend ready');
    const quick = name => page.locator(`[data-preset="builtin:${name}"]`);
    await page.locator('#preferences-btn').click();
    await page.locator('[data-theme-choice="crystal"]').click();
    await page.locator('#general-tab').click(); await page.locator('#language-select').selectOption('en');
    await page.locator('#preferences-close').click();
    await page.locator('#input-script').fill('-- @VM_START\nlocal function greet(name)\n  return STRING_OBF("hello, "), name\nend\nprint(greet("Karity"))\n-- @VM_END');
    await page.screenshot({animations:'disabled',path:path.join(shots,'workspace.png')});
    await quick('fast').click();
    await page.locator('[data-backend="mov"]').click();
    assert(!await page.locator('#backend-picker').isVisible());
    await quick('balanced').click();
    assert.equal(await page.locator('[data-backend="mov"]').getAttribute('aria-pressed'),'true');
    let prevented=false;
    await page.evaluate(()=>document.addEventListener('contextmenu',e=>{window.testContextPrevented=e.defaultPrevented;}));
    await quick('strong').click({button:'right'});
    assert.equal(await quick('balanced').getAttribute('aria-pressed'),'true');
    assert(await page.evaluate(()=>window.testContextPrevented));
    assert(await page.locator('#preset-picker').isVisible());
    await page.screenshot({animations:'disabled',path:path.join(shots,'presets.png')});
    await page.keyboard.press('ArrowRight'); await page.keyboard.press('Enter');
    assert(!await page.locator('#preset-picker').isVisible());
    assert.equal(await page.locator('[data-backend="mov"]').getAttribute('aria-pressed'),'true');
    await page.locator('#backend-details').focus(); await page.keyboard.press('Enter');
    assert(await page.locator('#backend-picker').isVisible());
    await page.keyboard.press('Escape');
    assert.equal(await page.evaluate(()=>document.activeElement.id),'backend-details');
    await page.locator('[data-backend="karity"]').click({button:'right'});
    assert.equal(await page.locator('[data-backend="mov"]').getAttribute('aria-pressed'),'true');
    await page.locator('[data-backend-choice="karity"]').click();
    assert.equal(await page.locator('[data-backend="karity"]').getAttribute('aria-pressed'),'true');
    await quick('fast').click();
    const source='local x=1\nprint(x)\nprint("tail")\n';
    await page.locator('#input-script').fill(source);
    await page.locator('#input-script').evaluate(el=>el.setSelectionRange(0,19));
    await page.locator('#marker-tools > summary').click();
    await page.locator('#marker-kind').selectOption('FUNCTION_OBF_START');
    await page.locator('[data-marker-option="junk"]').selectOption('false');
    await page.waitForFunction(()=>document.querySelector('#marker-options').value==='junk=false');
    await page.locator('#marker-advanced > summary').click();
    await page.locator('#marker-options').fill('junk_rate=0.1');
    await page.waitForFunction(()=>document.querySelector('#insert-marker-btn').disabled);
    await page.waitForFunction(()=>document.querySelector('#marker-hint').textContent.includes('unknown'));
    await page.locator('#marker-kind').selectOption('VM_START');
    await page.locator('#marker-options').fill('profile="fast-vm", junk_rate=0.05');
    await page.waitForFunction(()=>!document.querySelector('#insert-marker-btn').disabled);
    const preview=await page.locator('#marker-preview').textContent();
    assert(preview.includes('-- @VM_END\n')); assert(!preview.includes('tail'));
    await page.screenshot({animations:'disabled',path:path.join(shots,'marker.png')});
    await page.locator('#insert-marker-btn').click();
    await page.waitForFunction(()=>document.querySelector('#input-script').value.startsWith('-- @VM_START'));
    assert.equal(await page.locator('#input-script').inputValue(),preview+'print("tail")\n');
    await page.waitForFunction(()=>document.querySelector('.token-marker-start') && document.querySelector('.token-marker-end'));
    // A late options response must not leave an option-free macro disabled.
    await page.locator('#input-script').fill('print("quick")');
    await page.locator('#input-script').evaluate(el=>el.setSelectionRange(6,13));
    await page.locator('#marker-tools > summary').click();
    await page.locator('#marker-options').fill('bad_option=true');
    await page.locator('#marker-kind').selectOption('STRING_OBF');
    await page.waitForFunction(()=>!document.querySelector('#insert-marker-btn').disabled);
    assert.equal(await page.locator('#marker-preview').textContent(),'STRING_OBF("quick")');
    await page.locator('#marker-tools > summary').click();
    const literal='print(STRING_OBF("🌸한글"))';
    await page.locator('#input-script').fill(literal);
    await page.locator('#run-btn').click();
    await page.waitForFunction(()=>!document.querySelector('#build-progress').hidden);
    assert(await page.locator('#run-btn').isDisabled());
    await page.locator('#input-script').fill('print("edited during build")');
    await page.locator('[data-backend="mov"]').click();
    await page.screenshot({animations:'disabled',path:path.join(shots,'building.png')});
    await page.waitForFunction(()=>!document.querySelector('#run-btn').disabled,{timeout:120000});
    assert.equal(await page.locator('#status-msg').getAttribute('data-message'),'Protection complete');
    await page.locator('#inspect-output').click();
    const metrics=await page.locator('#inspector-body dd').allTextContents();
    assert.equal(metrics[0],Buffer.byteLength(literal)+' B'); assert.equal(metrics[5],'Karity');
    const output=await page.locator('#output-script').inputValue();
    assert.equal(metrics[1],Buffer.byteLength(output).toLocaleString()+' B');
    assert(await page.locator('#inspector-body .profile-detail').count()>0);
    await page.screenshot({animations:'disabled',path:path.join(shots,'inspector.png')});
    await page.keyboard.press('Escape');
    await page.locator('#source-view').click(); await page.locator('[data-backend="karity"]').click();
    await page.locator('#input-script').fill(literal); await page.locator('#run-btn').click();
    await page.waitForFunction(()=>!document.querySelector('#run-btn').disabled,{timeout:120000});
    await page.locator('#inspect-output').click();
    assert((await page.locator('#inspector-body').textContent()).includes('Same input and settings'));
    await page.keyboard.press('Escape');
    const successful=await page.locator('#output-script').inputValue();
    await page.locator('#source-view').click(); await page.locator('#input-script').fill('local function');
    await page.locator('#run-btn').click();
    await page.waitForFunction(()=>!document.querySelector('#run-btn').disabled,{timeout:120000});
    assert.equal(await page.locator('#status-msg').getAttribute('data-message'),'Build failed');
    assert.equal(await page.locator('#output-script').inputValue(),successful);
    await page.locator('#build-details').click();
    assert((await page.locator('#inspector-body').textContent()).includes('Previous successful result'));
    await page.keyboard.press('Control+k'); assert(!await page.locator('#command-palette').isVisible());
    await page.keyboard.press('Escape');
    await page.locator('#command-open').click();
    await page.locator('#command-query').fill('테마');
    assert.equal(await page.locator('#command-results li').count(),1);
    await page.keyboard.press('F5'); assert(await page.locator('#execution-console').isHidden());
    await page.screenshot({animations:'disabled',path:path.join(shots,'commands.png')});
    await page.keyboard.press('Enter');
    await page.waitForFunction(()=>document.activeElement.id==='appearance-tab');
    assert(await page.locator('#preferences-overlay').isVisible());
    const bootstrap=await call('get_bootstrap');
    for (const theme of Object.keys(bootstrap.themes)) {
      await page.locator(`[data-theme-choice="${theme}"]`).click();
      assert.equal(await page.locator(`[data-theme-choice="${theme}"]`).getAttribute('aria-pressed'),'true');
    }
    await page.locator('[data-theme-choice="crystal"]').click();
    await page.locator('#gui-tab').click();
    for (const density of ['comfortable','compact']) {
      await page.locator('#density-select').selectOption(density);
      await page.locator('#general-tab').click();
      for (const language of ['ko','en']) {
        await page.locator('#language-select').selectOption(language);
        await page.locator('#preferences-close').click();
        for (const size of [{width:1040,height:680},{width:1440,height:900}]) {
          await page.setViewportSize(size);
          await page.locator('#preset-details').click();
          await page.locator('#preset-picker').evaluate(el=>Promise.all(el.getAnimations().map(animation=>animation.finished.catch(()=>{}))));
          const box=await page.locator('#preset-picker').boundingBox();
          assert(box.x>=0 && box.y>=0 && box.width<=size.width && box.height<=size.height, JSON.stringify({box,size,language,density}));
          await page.keyboard.press('Escape');
          await page.locator('#command-open').click();
          assert((await page.locator('#command-label').textContent())===(language==='ko'?'명령 검색':'Search commands'));
          await page.keyboard.press('Escape');
        }
        await page.locator('#preferences-btn').click(); await page.locator('#general-tab').click();
      }
      await page.locator('#gui-tab').click();
    }
    await page.locator('[data-gui-choice="v1"]').click(); await page.locator('#preferences-close').click();
    await page.locator('#command-open').click(); assert(await page.locator('#command-palette').isVisible());
    await page.keyboard.press('Escape');
    assert.equal(await page.evaluate(()=>document.activeElement.id),'command-open');
    await page.locator('#preferences-btn').click(); await page.locator('#gui-tab').click();
    await page.locator('[data-gui-choice="v2"]').click(); await page.locator('#general-tab').click();
    await page.locator('#motion-select').selectOption('reduced'); await page.locator('#preferences-close').click();
    await page.locator('#preset-details').click();
    assert.equal(await page.locator('#preset-picker').evaluate(el=>getComputedStyle(el).animationName),'none');
    await page.keyboard.press('Escape');
    await page.locator('#build-dismiss').click();
    await page.locator('#source-view').click(); await page.locator('#input-script').fill('-- @VM_START\nprint("🌸한글")\n-- @VM_END');
    await page.screenshot({animations:'disabled',path:path.join(shots,'marker-emphasis.png')});
    assert.deepEqual(errors,[]);
    console.log('gui-experience-browser-ok real builds, selection, markers, inspector, commands, all themes, languages, densities, v1/v2');
  } finally {
    if(browser) await browser.close();
    await call('close').catch(()=>{});
    await new Promise(resolve=>{if(server.exitCode!==null)return resolve(); server.once('exit',resolve); setTimeout(()=>{server.kill();resolve();},5000).unref();});
  }
})().catch(error=>{console.error(error);process.exitCode=1;});
