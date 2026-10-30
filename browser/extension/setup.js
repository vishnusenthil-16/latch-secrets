const status = document.querySelector('#status');
const stored = await chrome.storage.local.get('label');
document.querySelector('#label').value = stored.label || '';
document.querySelector('#grant').onclick = async () => {
  try {
    const u = new URL(document.querySelector('#site').value);
    if (u.protocol !== 'https:' || u.username || u.password) throw 0;
    const allowed = await chrome.permissions.request({origins:[u.origin+'/*']});
    status.textContent = allowed ? 'Site access granted.' : 'Site access not granted.';
  } catch { status.textContent = 'Enter a valid HTTPS site.'; }
};
document.querySelector('#save').onclick = async () => {
  await chrome.storage.local.set({label:document.querySelector('#label').value});
  status.textContent = 'Profile label saved.';
};
document.querySelector('#connect').onclick = async () => {
  await chrome.runtime.sendMessage({op:'connect'});
  status.textContent = 'Connection requested. Run latch browser targets to verify.';
};
