/* modal.mjs — Esc、焦点、滚动锁与关闭清理。 */

export function openModalLock() {
  const prev = document.body.style.overflow;
  document.body.style.overflow = 'hidden';
  return () => {
    document.body.style.overflow = prev;
  };
}

export function bindEscape(onClose) {
  const handler = (ev) => {
    if (ev.key === 'Escape') onClose();
  };
  window.addEventListener('keydown', handler);
  return () => window.removeEventListener('keydown', handler);
}

export function focusFirst(root) {
  if (!root) return;
  const el = root.querySelector('input,button,textarea,select,[tabindex]:not([tabindex="-1"])');
  if (el && typeof el.focus === 'function') el.focus();
}
