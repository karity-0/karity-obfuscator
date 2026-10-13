/* Optional browser regression through the real API and temporary settings. */
const assert=require('node:assert/strict');
const path=require('node:path');
const {spawn}=require('node:child_process');
const {createInterface}=require('node:readline');
const {chromium}=require('playwright');
const root=path.resolve(__dirname,'..');
(async()=>{
  const server=spawn(process.env.KARITY_PYTHON||'python',[path.join(__dirname,'gui_web_server.py')],
    {cwd:root,windowsHide:true,stdio:['ignore','pipe','inherit']});
  const url=await new Promise((resolve,reject)=>{
    createInterface({input:server.stdout}).once('line',resolve);
    server.once('error',reject);server.once('exit',code=>reject(new Error('Bridge exit '+code)));
  });
  const call=async(method,...args)=>(await fetch(url+'/api',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({method,args})})).json();
  let browser;
  try{
    await call('save_preferences',{language:'ko',theme:'crystal'});
    browser=await chromium.launch({headless:true,...(process.env.KARITY_TEST_BROWSER?{executablePath:process.env.KARITY_TEST_BROWSER}:{})});
    const page=await browser.newPage({viewport:{width:1440,height:900}}),errors=[];
    page.on('pageerror',e=>errors.push(String(e)));
    await page.addInitScript(()=>{window.pywebview={api:new Proxy({},{get:(_,method)=>(...args)=>fetch('/api',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({method,args})}).then(r=>r.json())})};});
    await page.goto(url);
    await page.waitForFunction(()=>document.querySelector('#backend-label').textContent==='backend ready');
    await page.locator('[data-preset="builtin:fast"]').click();
    await page.locator('#settings-open').click();
    const row=label=>page.locator('.option-row').filter({has:page.locator('.option-label',{hasText:label})});
    assert.equal(await row('정수 연산 치환').count(),1);
    await page.locator('#target-lua_version').evaluate(e=>{e.value='5.1';e.dispatchEvent(new Event('change',{bubbles:true}));});
    assert(await row('정수 연산 치환').locator('input').first().isDisabled());
    assert(await row('공유 계산 재구성').locator('input').first().isDisabled());
    const notice=await row('정수 연산 치환').locator('.option-description').textContent();
    assert(notice.includes('미지원'),notice);
    assert.equal(await page.locator('html').getAttribute('lang'),'ko');
    await page.locator('#target-lua_version').evaluate(e=>{e.value='5.3';e.dispatchEvent(new Event('change',{bubbles:true}));});
    assert(await row('정수 연산 치환').locator('input').first().isEnabled());
    await page.locator('.option-row').filter({has:page.locator('.option-description',{hasText:/^backend$/})}).locator('select').evaluate(e=>{e.value='mov';e.dispatchEvent(new Event('change',{bubbles:true}));});
    assert(await row('블록 재배치 비율').locator('input').first().isDisabled());
    assert(await row('정수 연산 치환').locator('input').first().isEnabled());
    assert.equal(await page.locator('[data-preset="builtin:fast"]').getAttribute('aria-pressed'),'true');
    assert.deepEqual(errors,[]);
    console.log('gui-ir-smoke-ok Korean labels, Lua gate, MOV gate, independent preset');
  }finally{if(browser)await browser.close();await call('close');server.kill();}
})().catch(error=>{console.error(error);process.exitCode=1;});
