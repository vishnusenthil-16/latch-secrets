import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,writeFile} from 'node:fs/promises';
import {createServer} from 'node:http';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {waitForDevToolsEndpoint} from './cdp-ready.mjs';

test('CDP readiness waits for missing/partial port file and matching ready endpoint',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'latch-cdp-ready-'));
 let ready=false;
 const path='/devtools/browser/synthetic-ready-browser';
 const server=createServer((request,response)=>{
  assert.equal(request.url,'/json/version');
  response.writeHead(ready?200:503,{'content-type':'application/json'});
  response.end(JSON.stringify({webSocketDebuggerUrl:`ws://127.0.0.1:${server.address().port}${path}`}));
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const port=server.address().port;
 const publish=(async()=>{
  await delay(30);
  await writeFile(join(dir,'DevToolsActivePort'),`${port}\n`);
  await delay(30);
  await writeFile(join(dir,'DevToolsActivePort'),`${port}\n/devtools/browser/partial`);
  await delay(30);
  await writeFile(join(dir,'DevToolsActivePort'),`${port}\n${path}`);
  await delay(30);
  ready=true;
 })();
 try {
  assert.equal(await waitForDevToolsEndpoint(dir,{timeoutMs:2_000}),`ws://127.0.0.1:${port}${path}`);
  assert.equal(ready,true);
 } finally {
  await publish;
  server.closeAllConnections();
  await new Promise(resolve=>server.close(resolve));
  await rm(dir,{recursive:true,force:true});
 }
});

test('CDP readiness has a bounded failure when the port file never appears',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'latch-cdp-timeout-'));
 const started=performance.now();
 try {
  await assert.rejects(waitForDevToolsEndpoint(dir,{timeoutMs:50}),/did not become ready within 50ms/);
  assert.ok(performance.now()-started<1_000);
 } finally {await rm(dir,{recursive:true,force:true});}
});
