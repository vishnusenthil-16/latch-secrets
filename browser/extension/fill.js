export function fillDocument(rules, selector, value) {
  // Chrome scripting argument conversion can omit nested null properties.
  // The extension sends policy as JSON text to preserve explicit exact:null.
  if (typeof rules === 'string') rules = JSON.parse(rules);
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
