import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';

// Playwright's pipe connection can be ready before Chromium publishes its CDP
// TCP endpoint. Wait for a complete port file AND the corresponding HTTP server.
export async function waitForDevToolsEndpoint(profile, {timeoutMs=10_000}={}) {
 const deadline=performance.now()+timeoutMs;
 while(performance.now()<deadline) {
  let contents;
  try {
   contents=await readFile(join(profile,'DevToolsActivePort'),'utf8');
  } catch(error) {
   if(error.code!=='ENOENT') throw error;
  }
  const [port,path,...extra]=(contents??'').trim().split(/\r?\n/);
  if(extra.length===0 && /^[1-9]\d{0,4}$/.test(port) && Number(port)<=65535 &&
     /^\/devtools\/browser\/[a-zA-Z0-9-]+$/.test(path)) {
   const endpoint=`ws://127.0.0.1:${port}${path}`;
   const remaining=Math.ceil(deadline-performance.now());
   if(remaining<=0) break;
   try {
    const response=await fetch(`http://127.0.0.1:${port}/json/version`,{
     signal:AbortSignal.timeout(Math.min(remaining,500)),redirect:'error',
    });
    if(response.ok && (await response.json()).webSocketDebuggerUrl===endpoint) return endpoint;
   } catch {
    // A published port file does not yet guarantee a listening/ready endpoint.
   }
  }
  const remaining=deadline-performance.now();
  if(remaining>0) await delay(Math.min(25,remaining));
 }
 throw new Error(`Chromium CDP endpoint did not become ready within ${timeoutMs}ms`);
}
