import {test} from 'node:test';
import assert from 'node:assert/strict';
import {chromium} from 'playwright';
import {fill,fillDocument} from './fill.mjs';

test('document-bound fill, origin rejection, and field validation', async()=>{
 const browser=await chromium.launch({headless:true});
 try {
  const page=await browser.newPage();
  await page.route('https://fixture.test/**', route=>route.fulfill({
   contentType:'text/html',body:'<input id="password" type="password"><input id="text">'
  }));
  await page.goto('https://fixture.test/');
  const run=(origin,selector)=>page.evaluate(
   ({source,origin,selector})=>(0,eval)('('+source+')')(origin,selector,'dummy-only'),
   {source:fillDocument.toString(),origin,selector});
  assert.equal((await run('https://wrong.test','#password')).status,'rejected');
  assert.equal(await page.locator('#password').inputValue(),'');
  assert.equal((await run('https://fixture.test','#text')).status,'rejected');
  assert.deepEqual(await run('https://fixture.test','#password'),{status:'filled',fields:1});
  assert.equal(await page.locator('#password').inputValue(),'dummy-only');
 } finally {await browser.close();}
});

test('attaches to existing Chromium target through CDP',async()=>{
 const browser=await chromium.launch({headless:true,args:['--remote-debugging-port=19287']});
 try {
  const page=await browser.newPage();
  await page.route('https://fixture.test/**',r=>r.fulfill({contentType:'text/html',body:'<input id="p" type="password">'}));
  await page.goto('https://fixture.test/');
  const cdp=await page.context().newCDPSession(page);
  const {targetInfo}=await cdp.send('Target.getTargetInfo');
  const options={endpoint:'http://127.0.0.1:19287',target:targetInfo.targetId,origin:'https://fixture.test',selector:'#p',value:'dummy-only'};
  assert.equal((await fill({...options,origin:'https://wrong.test'})).status,'rejected');
  assert.equal((await fill({...options,target:'missing-target'})).status,'rejected');
  for (const attrs of [
   'disabled', 'readonly', 'style="display:none"', 'style="visibility:hidden"',
   'style="opacity:0"', 'style="position:absolute;left:-9999px"',
   'style="width:1px;height:1px;padding:0;border:0"'
  ]) {
   await page.setContent('<input id="p" type="password" '+attrs+'>');
   assert.equal((await fill(options)).status,'rejected',attrs);
  }
  await page.setContent('<input id="p" type="password"><input id="p" type="password">');
  assert.equal((await fill(options)).status,'rejected');
  await page.setContent('<input id="p" type="password">');
  assert.deepEqual(await fill(options),{status:'filled',fields:1});
  assert.equal(await page.locator('#p').inputValue(),'dummy-only');
 } finally {await browser.close();}
});

test('rejects opaque sandbox origin in isolated world',async()=>{
 const browser=await chromium.launch({headless:true});
 try {
  const page=await browser.newPage();
  await page.route('https://fixture.test/**',r=>r.fulfill({
   headers:{'Content-Security-Policy':'sandbox allow-scripts'},
   contentType:'text/html',body:'<input id="p" type="password">'
  }));
  await page.goto('https://fixture.test/');
  const cdp=await page.context().newCDPSession(page);
  const {frameTree}=await cdp.send('Page.getFrameTree');
  const {executionContextId}=await cdp.send('Page.createIsolatedWorld',{frameId:frameTree.frame.id,worldName:'test'});
  const result=await cdp.send('Runtime.callFunctionOn',{
   executionContextId,functionDeclaration:fillDocument.toString(),
   arguments:['https://fixture.test','#p','dummy-only'].map(value=>({value})),returnByValue:true
  });
  assert.deepEqual(result.result.value,{status:'rejected'});
  assert.equal(await page.locator('#p').inputValue(),'');
 } finally {await browser.close();}
});

async function world(cdp, frameId) {
 return (await cdp.send('Page.createIsolatedWorld',{frameId,worldName:'safety-test'})).executionContextId;
}
async function invoke(cdp, executionContextId) {
 return cdp.send('Runtime.callFunctionOn',{
  executionContextId,functionDeclaration:fillDocument.toString(),
  arguments:['https://fixture.test','#p','dummy-only'].map(value=>({value})),returnByValue:true
 });
}

test('isolated-world subframe rejection and stale-document navigation',async()=>{
 const browser=await chromium.launch({headless:true});
 try {
  const page=await browser.newPage();
  await page.route('https://fixture.test/**',r=>r.fulfill({contentType:'text/html',body:
   '<input id="p" type="password">'+(r.request().url().endsWith('/child')?'':'<iframe src="/child"></iframe>')}));
  await page.goto('https://fixture.test/');
  const cdp=await page.context().newCDPSession(page);
  const {frameTree}=await cdp.send('Page.getFrameTree');
  const childWorld=await world(cdp,frameTree.childFrames[0].frame.id);
  assert.deepEqual((await invoke(cdp,childWorld)).result.value,{status:'rejected'});
  assert.equal(await page.frames()[1].locator('#p').inputValue(),'');
  const oldWorld=await world(cdp,frameTree.frame.id);
  await page.goto('https://fixture.test/replacement');
  await assert.rejects(invoke(cdp,oldWorld));
  assert.equal(await page.locator('#p').inputValue(),'');
 } finally {await browser.close();}
});

test('CLI metadata-only success, rejection and error output',async()=>{
 const {spawn}=await import('node:child_process');
 const {mkdtemp,readFile,rm}=await import('node:fs/promises');
 const {tmpdir}=await import('node:os');
 const {join}=await import('node:path');
 const dir=await mkdtemp(join(tmpdir(),'latch-browser-test-'));
 const context=await chromium.launchPersistentContext(dir,{headless:true,args:['--remote-debugging-port=0']});
 try {
  const port=(await readFile(join(dir,'DevToolsActivePort'),'utf8')).split('\n')[0];
  const page=context.pages()[0];
  await page.route('https://fixture.test/**',r=>r.fulfill({contentType:'text/html',body:'<form><input id="p" type="password"></form>'}));
  await page.goto('https://fixture.test/');
  const cdp=await context.newCDPSession(page);
  const {targetInfo}=await cdp.send('Target.getTargetInfo');
  const base={endpoint:`http://127.0.0.1:${port}`,target:targetInfo.targetId,origin:'https://fixture.test',selector:'#p',env:'LATCH_TEST_PASSWORD'};
  const run=(changes={},missing=false)=>new Promise((resolve,reject)=>{
   const env={...process.env,DEBUG:'pw:protocol',PWDEBUG:'0'};
   delete env.LATCH_TEST_PASSWORD;
   if(!missing) env.LATCH_TEST_PASSWORD='dummy-cli-only';
   const child=spawn(process.execPath,[new URL('./fill.mjs',import.meta.url).pathname,...Object.entries({...base,...changes}).flatMap(([k,v])=>['--'+k,v])],{env});
   let stdout='',stderr='';
   child.stdout.on('data',b=>stdout+=b); child.stderr.on('data',b=>stderr+=b);
   child.on('error',reject); child.on('close',code=>resolve({code,stdout,stderr}));
  });
  assert.deepEqual(await run(),{code:0,stdout:'{"status":"filled","fields":1}\n',stderr:''});
  assert.equal(await page.locator('#p').inputValue(),'dummy-cli-only');
  assert.equal(page.url(),'https://fixture.test/');
  for(const changes of [{origin:'https://wrong.test'},{target:'missing'}])
   assert.deepEqual(await run(changes),{code:1,stdout:'{"status":"rejected"}\n',stderr:''});
  for(const changes of [{endpoint:'http://example.com:9222'},{origin:'http://example.com'},{selector:'['},{password:'dummy-cli-only'}])
   assert.deepEqual(await run(changes),{code:1,stdout:'{"status":"failed","outcome":"unknown"}\n',stderr:''});
  assert.deepEqual(await run({},true),{code:1,stdout:'{"status":"failed","outcome":"unknown"}\n',stderr:''});
 } finally {await context.close();await rm(dir,{recursive:true,force:true});}
});
