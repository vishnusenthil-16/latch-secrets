import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile, writeFile, mkdtemp, rm, cp, readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {createConnection} from 'node:net';
import {chromium} from 'playwright';

const workerSource = await readFile(new URL('../../browser/extension/worker.js',import.meta.url),'utf8');
const fillSource = await readFile(new URL('../../browser/extension/fill.js',import.meta.url),'utf8');
const {dispatch} = await import('data:text/javascript;base64,'+Buffer.from(
  workerSource.replace("import {fillDocument} from './fill.js';",fillSource)).toString('base64'));
const rules = [{origin:'https://example.test',exact:null}];
const canary = 'CANARY_private_bridge';
function fixture() {
  let calls = 0;
  const frame = {documentId:'doc1',documentLifecycle:'active',url:'https://example.test/login'};
  const api = {
    storage:{local:{get:async()=>({profileId:'profile',label:'Test'}),set:async()=>{}}},
    tabs:{query:async()=>[{id:1,url:frame.url,title:'Login',windowId:1,active:true},
      {id:2,url:'https://unrelated.test',title:'Private unrelated tab'}]},
    permissions:{contains:async()=>true},
    webNavigation:{getFrame:async()=>({...frame})},
    scripting:{executeScript:async o=>{calls++; assert.equal(o.world,'ISOLATED');assert.deepEqual(o.target,{tabId:1,documentIds:['doc1']});assert.equal(o.args[2],canary);return [{documentId:'doc1',result:true}];}},
  };
  return {api,frame,calls:()=>calls};
}
async function request(f, now=0, policy=rules) {
  const t = await dispatch({op:'targets',rules:policy},f.api,now);
  assert.equal(t.targets.length,1);
  assert.ok(!JSON.stringify(t).includes('unrelated'));
  return {op:'fill',rules:policy,handle:t.targets[0].handle,selector:'#p',value:canary};
}
test('bridge document binding, single use, expiry, schema, policy, and uncertain dispatch',async()=>{
  let f=fixture(); let r=await request(f);
  assert.deepEqual(await dispatch({...r},f.api,1),{status:'filled'});
  assert.deepEqual(await dispatch(r,f.api,2),{status:'rejected'}); assert.equal(f.calls(),1);
  for (const mutate of [f=>f.frame.documentId='doc2',f=>f.frame.url='https://evil.test',
    f=>f.frame.documentLifecycle='cached']) {
    f=fixture();r=await request(f);mutate(f);
    assert.deepEqual(await dispatch(r,f.api,1),{status:'rejected'});assert.equal(f.calls(),0);
  }
  f=fixture();r=await request(f,0,[{origin:rules[0].origin,exact:'https://example.test/login'}]);
  f.frame.url='https://example.test/other';
  assert.deepEqual(await dispatch(r,f.api,1),{status:'rejected'});
  f=fixture();r=await request(f);assert.deepEqual(await dispatch(r,f.api,60000),{status:'rejected'});
  f=fixture();r=await request(f);f.api.scripting.executeScript=async()=>{throw Error(canary)};
  const result=await dispatch({...r},f.api,1); assert.deepEqual(result,{status:'outcome_unknown'});
  assert.ok(!JSON.stringify(result).includes(canary));assert.deepEqual(await dispatch(r,f.api,2),{status:'rejected'});
  assert.deepEqual(await dispatch({op:'eval',rules,script:'anything'},f.api),{status:'rejected'});
  assert.deepEqual(await dispatch({op:'targets',rules,extra:'anything'},f.api),{status:'rejected'});
  f=fixture();f.api.permissions.contains=async()=>false;
  assert.deepEqual(await dispatch({op:'targets',rules},f.api),{status:'ok',targets:[]});
});

test('real native host + MV3 extension: existing document, isolated fill, navigation and replay',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'latch-extension-test-'));
  const extension=join(dir,'extension');
  await cp(new URL('../../browser/extension/',import.meta.url),extension,{recursive:true});
  const manifest=JSON.parse(await readFile(join(extension,'manifest.json'),'utf8'));
  // Fixture pregrants only the synthetic site. Production permissions require a user gesture.
  manifest.host_permissions=['https://example.test/*'];
  await writeFile(join(extension,'manifest.json'),JSON.stringify(manifest));
  const binary=join(dir,'latch');
  await cp(new URL('../../target/debug/latch',import.meta.url),binary);
  execFileSync(binary,['browser','install-host','--browser','chrome-for-testing','--user-data-dir',join(dir,'profile')],{env:{...process.env,HOME:dir}});
  const runtime=`/tmp/latch-browser-${process.getuid()}`;
  const before=await readdir(runtime).catch(()=>[]);
  const context=await chromium.launchPersistentContext(join(dir,'profile'),{channel:'chromium',headless:true,env:{...process.env,HOME:dir},
    args:[`--disable-extensions-except=${extension}`,`--load-extension=${extension}`]});
  try {
    if (!context.serviceWorkers().length) await context.waitForEvent('serviceworker');
    await context.route('https://example.test/**',r=>r.fulfill({contentType:'text/html',body:'<input id="p" type="password">'}));
    const page=await context.newPage();await page.goto('https://example.test/login');
    let socket;
    for(let i=0;i<50;i++){socket=(await readdir(runtime).catch(()=>[])).find(s=>!before.includes(s));if(socket)break;await new Promise(r=>setTimeout(r,20));}
    assert.ok(socket,'Chrome must launch the installed native host');
    const call = request => new Promise((resolve,reject)=>{
      const stream=createConnection(join(runtime,socket));
      let response=Buffer.alloc(0);
      stream.setTimeout(20_000,()=>stream.destroy(new Error('bridge timeout')));
      stream.on('error',reject);
      stream.on('connect',()=>{
        const body=Buffer.from(JSON.stringify(request));
        const header=Buffer.alloc(4);header.writeUInt32LE(body.length);
        stream.write(Buffer.concat([header,body]));
      });
      stream.on('data',chunk=>{
        response=Buffer.concat([response,chunk]);
        if(response.length>=4 && response.length>=4+response.readUInt32LE(0)){
          stream.end();resolve(JSON.parse(response.subarray(4).toString()));
        }
      });
    });
    const discover=async()=> (await call({op:'targets',rules})).targets;
    let targets=await discover();assert.equal(targets.length,1);
    const fill=handle=>call({op:'fill',rules,handle,selector:'#p',value:canary});
    assert.deepEqual(await fill(targets[0].handle),{status:'filled',fields:1});
    assert.equal(await page.locator('#p').inputValue(),canary);
    assert.deepEqual(await fill(targets[0].handle),{status:'rejected'});
    targets=await discover();await page.goto('https://example.test/other');
    assert.deepEqual(await fill(targets[0].handle),{status:'rejected'});
    assert.equal(await page.locator('#p').inputValue(),'');
    targets=await discover();await page.locator('#p').evaluate(e=>e.style.opacity='0');
    assert.deepEqual(await fill(targets[0].handle),{status:'rejected'});
  } finally {await context.close();await rm(dir,{recursive:true,force:true});}
});
