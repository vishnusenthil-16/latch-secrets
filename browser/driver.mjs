// Embedded in the Rust binary. No credential arguments, environment or output.
// Exit 0: filled, 10: rejected before fill, 11: unknown outcome. Never retry.
function fillDocument(rules, selector, value) {
  if (window !== window.top || self.origin === 'null' || location.protocol !== 'https:' ||
      !rules.some(r => self.origin === r.origin && location.origin === r.origin &&
        (r.exact === null || location.href === r.exact))) return false;
  const matches = document.querySelectorAll(selector);
  if (matches.length !== 1) return false;
  const field = matches[0];
  if (!(field instanceof HTMLInputElement) || field.type !== 'password' ||
      !field.isConnected || field.disabled || field.readOnly || field.closest('[inert]') ||
      !field.checkVisibility({opacityProperty:true,visibilityProperty:true})) return false;
  const rect = field.getBoundingClientRect();
  if (rect.width < 8 || rect.height < 8 || rect.left < 0 || rect.top < 0 ||
      rect.right > innerWidth || rect.bottom > innerHeight) return false;
  for (let e = field; e; e = e.parentElement) {
    const s = getComputedStyle(e);
    if (Number(s.opacity) < 1 || s.clipPath !== 'none' || s.clip !== 'auto' ||
        s.filter !== 'none' || s.transform !== 'none') return false;
    if (e !== field && [s.overflowX,s.overflowY].some(v => v !== 'visible')) {
      const r = e.getBoundingClientRect();
      if (rect.left < r.left || rect.right > r.right || rect.top < r.top || rect.bottom > r.bottom) return false;
    }
  }
  // Reject occlusion, including ancestor clipping, at inset corners and center.
  for (const [x,y] of [[rect.left+2,rect.top+2],[rect.right-2,rect.top+2],
      [rect.left+2,rect.bottom-2],[rect.right-2,rect.bottom-2],
      [rect.left+rect.width/2,rect.top+rect.height/2]]) {
    if (document.elementFromPoint(x,y) !== field) return false;
  }
  const style = getComputedStyle(field);
  if (style.color === 'transparent' || /^rgba\([^)]*,\s*0\)$/.test(style.color) ||
      style.webkitTextFillColor === 'transparent' || /^rgba\([^)]*,\s*0\)$/.test(style.webkitTextFillColor)) return false;
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(field,value);
  field.dispatchEvent(new Event('input',{bubbles:true}));
  field.dispatchEvent(new Event('change',{bubbles:true}));
  return true;
}

const deadline = setTimeout(() => process.exit(11), 15000);
try {
  let input = '';
  for await (const chunk of process.stdin) { input += chunk; if (input.length > 1048576) throw 0; }
  const {endpoint,target,rules,selector,value} = JSON.parse(input);
  input = '';
  const socket = new WebSocket(endpoint);
  let next = 0;
  const pending = new Map();
  socket.addEventListener('message', event => {
    try {
      const m = JSON.parse(event.data);
      const p = pending.get(m.id);
      if (p) { pending.delete(m.id); m.error ? p.reject(0) : p.resolve(m.result); }
    } catch { process.exit(11); }
  });
  socket.addEventListener('error', () => process.exit(11));
  socket.addEventListener('close', () => process.exit(11));
  await new Promise(resolve => socket.addEventListener('open',resolve,{once:true}));
  const call = (method,params={},sessionId) => new Promise((resolve,reject) => {
    const id = ++next; pending.set(id,{resolve,reject});
    socket.send(JSON.stringify({id,method,params,...(sessionId ? {sessionId} : {})}));
  });
  const {targetInfos} = await call('Target.getTargets');
  if (!targetInfos.some(t => t.targetId === target && t.type === 'page')) process.exit(10);
  const {sessionId} = await call('Target.attachToTarget',{targetId:target,flatten:true});
  const {frameTree} = await call('Page.getFrameTree',{},sessionId);
  const {executionContextId} = await call('Page.createIsolatedWorld',{
    frameId:frameTree.frame.id,worldName:'latch-fill'
  },sessionId);
  const result = await call('Runtime.callFunctionOn',{
    executionContextId,functionDeclaration:fillDocument.toString(),
    arguments:[rules,selector,value].map(value=>({value})),returnByValue:true
  },sessionId);
  if (result.exceptionDetails) process.exit(11);
  process.exit(result.result?.value === true ? 0 : 10);
} catch { process.exit(11); }
clearTimeout(deadline);
