import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile,mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawn} from 'node:child_process';
import {chromium} from 'playwright';
const driver = await readFile(new URL('../../browser/driver.mjs',import.meta.url),'utf8');
const source = driver.slice(driver.indexOf('function fillDocument'),driver.indexOf('\nconst deadline'));
const rules = [{origin:'https://fixture.test',exact:null}];
const run = payload => new Promise((resolve,reject)=>{
 const child=spawn(process.execPath,['--input-type=module','--eval',driver],{env:{PATH:process.env.PATH}});
 let stdout='',stderr='';
 child.stdout.on('data',b=>stdout+=b);child.stderr.on('data',b=>stderr+=b);
 child.on('error',reject);child.on('close',code=>resolve({code,stdout,stderr}));
 child.stdin.end(JSON.stringify(payload));
});

test('supported bundled driver: CDP, policy, visibility, metadata-only and no submit',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'latch-supported-'));
 const context=await chromium.launchPersistentContext(dir,{headless:true,args:['--remote-debugging-port=0']});
 try {
  const [port,path]=(await readFile(join(dir,'DevToolsActivePort'),'utf8')).trim().split('\n');
  const page=context.pages()[0];
  await page.route('https://fixture.test/**',r=>r.fulfill({contentType:'text/html',body:'<input id="p" type="password">'}));
  await page.goto('https://fixture.test/login');
  const cdp=await context.newCDPSession(page);
  const {targetInfo}=await cdp.send('Target.getTargetInfo');
  const base={endpoint:`ws://127.0.0.1:${port}${path}`,target:targetInfo.targetId,rules,selector:'#p',value:'synthetic-supported-canary'};
  const check=async(payload,code)=>assert.deepEqual(await run(payload),{code,stdout:'',stderr:''});
  await check({...base,target:'missing'},10);
  await check({...base,rules:[{origin:'https://wrong.test',exact:null}]},10);
  await check({...base,rules:[{origin:'https://fixture.test',exact:'https://fixture.test/other'}]},10);
  for(const html of [
   '<input id="p" type="password" style="opacity:.01">',
   '<input id="p" type="password" style="clip-path:inset(50%)">',
   '<div style="width:0;height:0;overflow:hidden"><input id="p" type="password"></div>',
   '<input id="p" type="password"><div style="position:fixed;inset:0;background:white"></div>',
   '<input id="p" type="password" style="color:transparent">',
   '<div inert><input id="p" type="password"></div>',
   '<input id="p" type="password" disabled>',
   '<input id="p" type="password" readonly>',
   '<input id="p" type="password"><input id="p" type="password">'
  ]) {await page.setContent(html);await check(base,10);assert.equal(await page.locator('#p').first().inputValue(),'');}
  await page.setContent('<form><input id="p" type="password"></form>');
  await check({...base,selector:'['},11);
  await check({...base,rules:[{origin:'https://fixture.test',exact:'https://fixture.test/login'}]},0);
  assert.equal(await page.locator('#p').inputValue(),base.value);
  assert.equal(page.url(),'https://fixture.test/login');
 } finally {await context.close();await rm(dir,{recursive:true,force:true});}
});

test('supported isolated-world origin/frame/navigation safeguards and page-read boundary',async()=>{
 const browser=await chromium.launch({headless:true});
 try {
  const page=await browser.newPage();
  await page.route('https://fixture.test/**',r=>r.fulfill({contentType:'text/html',
   headers:r.request().url().endsWith('/sandbox')?{'Content-Security-Policy':'sandbox allow-scripts'}:{},
   body:'<input id="p" type="password"><script>document.querySelector("#p").addEventListener("input",e=>window.observed=e.target.value)</script>'+(r.request().url().endsWith('/parent')?'<iframe src="/child"></iframe>':'')}));
  await page.goto('https://fixture.test/parent');
  const cdp=await page.context().newCDPSession(page);
  const world=async(frameId)=>(await cdp.send('Page.createIsolatedWorld',{frameId,worldName:'supported-test'})).executionContextId;
  const invoke=id=>cdp.send('Runtime.callFunctionOn',{executionContextId:id,functionDeclaration:source,arguments:[rules,'#p','synthetic-boundary-canary'].map(value=>({value})),returnByValue:true});
  let {frameTree}=await cdp.send('Page.getFrameTree');
  assert.equal((await invoke(await world(frameTree.childFrames[0].frame.id))).result.value,false);
  const old=await world(frameTree.frame.id);
  await page.goto('https://fixture.test/replacement');
  await assert.rejects(invoke(old));
  assert.equal(await page.locator('#p').inputValue(),'');
  ({frameTree}=await cdp.send('Page.getFrameTree'));
  assert.equal((await invoke(await world(frameTree.frame.id))).result.value,true);
  // An authorized site (and another debugger) CAN read the secret. This is not
  // an isolation boundary; never claim arbitrary external traces are sanitized.
  assert.equal(await page.evaluate(()=>window.observed),'synthetic-boundary-canary');
  await page.goto('https://fixture.test/sandbox');
  ({frameTree}=await cdp.send('Page.getFrameTree'));
  assert.equal((await invoke(await world(frameTree.frame.id))).result.value,false);
 } finally {await browser.close();}
});
