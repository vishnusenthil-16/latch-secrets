import { parseArgs } from 'node:util';
import { pathToFileURL } from 'node:url';

// Runs in a document-specific isolated world. Never return field values.
export function fillDocument(origin, selector, value) {
  if (location.origin !== origin || self.origin !== origin || window !== window.top) return {status:'rejected'};
  const matches = document.querySelectorAll(selector);
  if (matches.length !== 1) return {status:'rejected'};
  const field = matches[0];
  if (!(field instanceof HTMLInputElement) || field.type !== 'password' ||
      !field.isConnected || field.disabled || field.readOnly ||
      field.getClientRects().length === 0) return {status:'rejected'};
  const rect = field.getBoundingClientRect();
  if (!field.checkVisibility({opacityProperty:true, visibilityProperty:true}) ||
      rect.width < 2 || rect.height < 2 ||
      rect.right <= 0 || rect.bottom <= 0 ||
      rect.left >= innerWidth || rect.top >= innerHeight) return {status:'rejected'};
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(field, value);
  field.dispatchEvent(new Event('input', {bubbles:true}));
  field.dispatchEvent(new Event('change', {bubbles:true}));
  return {status:'filled', fields:1};
}

export async function fill({endpoint, target, origin, selector, value}) {
  const address = new URL(endpoint);
  const destination = new URL(origin);
  if (!['http:','ws:'].includes(address.protocol) ||
      !['localhost','127.0.0.1','[::1]'].includes(address.hostname) ||
      address.username || address.password ||
      destination.origin !== origin ||
      !(destination.protocol === 'https:' ||
        (destination.protocol === 'http:' && ['localhost','127.0.0.1','[::1]'].includes(destination.hostname))))
    throw new Error('invalid configuration');
  // Import after disabling protocol debug output.
  delete process.env.DEBUG;
  delete process.env.PWDEBUG;
  const {chromium} = await import('playwright');
  const browser = await chromium.connectOverCDP(endpoint, {timeout:10000});
  try {
    for (const context of browser.contexts()) for (const page of context.pages()) {
      const cdp = await context.newCDPSession(page);
      try {
        const {targetInfo} = await cdp.send('Target.getTargetInfo');
        if (targetInfo.targetId !== target) continue;
        const {frameTree} = await cdp.send('Page.getFrameTree');
        const {executionContextId} = await cdp.send('Page.createIsolatedWorld', {
          frameId:frameTree.frame.id, worldName:'latch-prototype'
        });
        const result = await cdp.send('Runtime.callFunctionOn', {
          executionContextId, functionDeclaration:fillDocument.toString(),
          arguments:[origin,selector,value].map(value=>({value})), returnByValue:true
        });
        if (result.exceptionDetails) return {status:'failed', outcome:'unknown'};
        return result.result.value ?? {status:'failed', outcome:'unknown'};
      } finally { await cdp.detach(); }
    }
    return {status:'rejected'};
  } finally { await browser.close(); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let result;
  try {
    const {values} = parseArgs({options:Object.fromEntries(
      ['endpoint','target','origin','selector','env'].map(key=>[key,{type:'string'}])
    )});
    const value = process.env[values.env];
    delete process.env[values.env];
    if (!value) throw new Error('missing input');
    result = await fill({...values,value});
  } catch { result = {status:'failed', outcome:'unknown'}; }
  process.stdout.write(JSON.stringify(result)+'\n');
  process.exitCode = result.status === 'filled' ? 0 : 1;
}
