import {fillDocument} from './fill.js';

const HOST = 'com.latch_secrets.browser';
const TTL = 60_000;
let port;
let connecting = false;
let busy = false;
let handles = new Map();
const keys = (o, expected) => o && typeof o === 'object' && !Array.isArray(o) &&
  Object.keys(o).sort().join(',') === expected.sort().join(',');
const validRules = rules => Array.isArray(rules) && rules.length > 0 && rules.length <= 256 &&
  rules.every(r => keys(r, ['origin', 'exact']) && typeof r.origin === 'string' &&
    r.origin.startsWith('https://') && (r.exact === null || typeof r.exact === 'string'));
const matches = (url, rules) => {
  try { const u = new URL(url); return u.protocol === 'https:' && rules.some(r =>
    u.origin === r.origin && (r.exact === null || url === r.exact)); } catch { return false; }
};

// A new port has a new handle namespace. Nothing is queued or replayed on reconnect.
export async function dispatch(request, api = chrome, now = performance.now()) {
  if (!request || !validRules(request.rules)) return {status:'rejected'};
  for (const [key, h] of handles) if (now - h.created >= TTL) handles.delete(key);
  if (request.op === 'targets' && keys(request, ['op','rules'])) {
    const stored = await api.storage.local.get(['profileId','label']);
    const profile = stored.profileId || crypto.randomUUID();
    if (!stored.profileId) await api.storage.local.set({profileId:profile});
    const targets = [];
    for (const tab of await api.tabs.query({})) {
      if (targets.length >= 128 || !matches(tab.url, request.rules)) continue;
      if (!await api.permissions.contains({origins:[new URL(tab.url).origin + '/*']})) continue;
      let frame;
      try { frame = await api.webNavigation.getFrame({tabId:tab.id,frameId:0}); } catch { continue; }
      if (!frame?.documentId || frame.documentLifecycle !== 'active' || !matches(frame.url,request.rules)) continue;
      const handle = crypto.randomUUID();
      if (handles.size >= 512) handles.delete(handles.keys().next().value);
      handles.set(handle, {tabId:tab.id,documentId:frame.documentId,created:now});
      targets.push({handle,origin:new URL(frame.url).origin,title:(tab.title || '').slice(0,256),
        active:!!tab.active,window:tab.windowId,profile,label:String(stored.label || '').slice(0,80)});
    }
    return {status:'ok',targets};
  }
  if (request.op !== 'fill' || !keys(request,['op','rules','handle','selector','value']) ||
      typeof request.handle !== 'string' || typeof request.selector !== 'string' ||
      !request.selector.length || request.selector.length > 4096 ||
      typeof request.value !== 'string' || !request.value.length) return {status:'rejected'};
  const h = handles.get(request.handle);
  handles.delete(request.handle); // one attempt, including rejected/uncertain attempts
  if (!h) return {status:'rejected'};
  let frame;
  try { frame = await api.webNavigation.getFrame({tabId:h.tabId,frameId:0}); } catch { return {status:'rejected'}; }
  if (!frame || frame.documentId !== h.documentId || frame.documentLifecycle !== 'active' ||
      !matches(frame.url, request.rules)) return {status:'rejected'};
  try {
    const results = await api.scripting.executeScript({target:{tabId:h.tabId,documentIds:[h.documentId]},
      world:'ISOLATED',func:fillDocument,args:[JSON.stringify(request.rules),request.selector,request.value]});
    if (results.length !== 1 || results[0].documentId !== h.documentId) return {status:'outcome_unknown'};
    return {status:results[0].result === true ? 'filled' : results[0].result === false ? 'rejected' : 'outcome_unknown'};
  } catch { return {status:'outcome_unknown'}; }
  finally { request.value = ''; }
}

function connect() {
  if (port || connecting) return;
  connecting = true;
  try {
    const current = chrome.runtime.connectNative(HOST);
    port = current;
    handles = new Map();
    current.onMessage.addListener(async request => {
      if (busy) { current.postMessage({status:'rejected'}); return; }
      busy = true;
      let result;
      try { result = await dispatch(request); } catch { result = {status:request?.op === 'fill' ? 'outcome_unknown' : 'rejected'}; }
      finally { busy = false; }
      // Never deliver an old request's result on a new connection.
      if (port === current) { try { current.postMessage(result); } catch {} }
    });
    current.onDisconnect.addListener(() => {
      void chrome.runtime.lastError;
      if (port === current) { port = undefined; handles.clear(); }
      // No automatic request retry. Reconnect when the user opens setup or Chrome starts.
    });
  } finally { connecting = false; }
}
if (typeof chrome !== 'undefined' && chrome.runtime?.connectNative) {
  const invalidate = event => {
    if (event.frameId !== 0) return;
    for (const [key,h] of handles) if (h.tabId === event.tabId) handles.delete(key);
  };
  chrome.webNavigation.onCommitted.addListener(invalidate);
  chrome.webNavigation.onHistoryStateUpdated.addListener(invalidate);
  chrome.tabs.onRemoved.addListener(tabId => invalidate({tabId,frameId:0}));
  chrome.runtime.onStartup.addListener(connect);
  chrome.runtime.onInstalled.addListener(connect);
  chrome.runtime.onMessage.addListener((request, sender, reply) => {
    if (sender.id === chrome.runtime.id && request?.op === 'connect') { connect(); reply({connected:!!port}); }
  });
  connect();
}
