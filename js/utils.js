/* ================================================
   PARAM MAKERSPACE — Utility Functions
   ================================================ */

/* --- String Helpers --- */
const slugify = str =>
  str.toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

const getInitials = name =>
  (name || '?').split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2);

const truncate = (str, n = 100) =>
  str && str.length > n ? str.slice(0, n).trimEnd() + '…' : str;

/* --- Date Helpers --- */
const formatDate = (iso, opts = {}) => {
  if (!iso) return '';
  return new Date(iso).toLocaleDateString('en-IN', {
    day: 'numeric', month: 'short', year: 'numeric', ...opts
  });
};

const relativeTime = iso => {
  if (!iso) return '';
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1)    return 'just now';
  if (mins < 60)   return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24)    return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30)   return `${days}d ago`;
  return formatDate(iso);
};

/* --- DOM Helpers --- */
const $ = id => document.getElementById(id);
const $$ = sel => document.querySelectorAll(sel);

const show = el => { if (el) el.classList.remove('hidden'); };
const hide = el => { if (el) el.classList.add('hidden'); };
const toggle = (el, condition) => condition ? show(el) : hide(el);

/* --- Alert Banner --- */
const showAlert = (containerId, message, type = 'error') => {
  const el = $(containerId);
  if (!el) return;
  el.className = `alert alert-${type}`;
  el.textContent = message;
  el.classList.remove('hidden');
  if (type === 'success') setTimeout(() => el.classList.add('hidden'), 4000);
};

const clearAlert = id => { const el = $(id); if (el) el.classList.add('hidden'); };

/* --- Loading State on Button --- */
const btnLoading = (btn, loading, original) => {
  if (!btn) return;
  btn.disabled = loading;
  btn.textContent = loading ? 'Please wait…' : original;
};

/* --- Render Helpers --- */
const renderBadge = (text, type = 'grey') =>
  `<span class="badge badge-${type}">${text}</span>`;

const renderAvatar = (name, size = '') =>
  `<div class="avatar ${size}">${getInitials(name)}</div>`;

const tierBadge = tier => {
  const map = { T1: 'badge-grey', T2: 'badge-blue', T3: 'badge-dark' };
  return renderBadge(tier, (map[tier] || 'badge-grey').replace('badge-', ''));
};

const statusBadge = status => {
  const map = {
    active: 'green', open: 'green', approved: 'green', completed: 'blue',
    pending: 'yellow', draft: 'grey', rejected: 'red', closed: 'dark'
  };
  return renderBadge(status, map[status] || 'grey');
};

/* --- Nav Active Link --- */
const setActiveNav = () => {
  const page = location.pathname.split('/').pop() || 'index.html';
  document.querySelectorAll('.nav-links a').forEach(a => {
    const href = a.getAttribute('href');
    if (href && page.startsWith(href.replace('.html', ''))) {
      a.classList.add('active');
    }
  });
};

/* --- Mobile Nav Toggle --- */
const initMobileNav = () => {
  const toggle = document.querySelector('.nav-toggle');
  const links  = document.querySelector('.nav-links');
  if (toggle && links) {
    toggle.addEventListener('click', () => links.classList.toggle('open'));
  }
};

/* --- Tabs --- */
const initTabs = (containerSel = '[data-tabs]') => {
  document.querySelectorAll(containerSel).forEach(container => {
    const btns   = container.querySelectorAll('.tab-btn');
    const panels = container.querySelectorAll('.tab-panel');

    btns.forEach((btn, i) => {
      btn.addEventListener('click', () => {
        btns.forEach(b => b.classList.remove('active'));
        panels.forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        if (panels[i]) panels[i].classList.add('active');
      });
    });

    // activate first by default
    if (btns[0])   btns[0].classList.add('active');
    if (panels[0]) panels[0].classList.add('active');
  });
};

/* --- URL Query Params --- */
const getParam = key => new URLSearchParams(location.search).get(key);

/* --- Clipboard --- */
const copyText = async text => {
  try { await navigator.clipboard.writeText(text); return true; }
  catch { return false; }
};

/* --- Format Number --- */
const fmtNum = n => Number(n || 0).toLocaleString('en-IN');

/* --- On DOM Ready --- */
const onReady = fn => {
  if (document.readyState !== 'loading') fn();
  else document.addEventListener('DOMContentLoaded', fn);
};
