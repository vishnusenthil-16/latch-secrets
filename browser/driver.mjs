// fillDocument is prepended by the Rust binary.

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
