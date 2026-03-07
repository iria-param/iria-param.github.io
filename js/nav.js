/* ================================================
   PARAM MAKERSADDA — Shared Nav + Footer Renderer
   ================================================ */

const NAV_LINKS = [
  { href: 'explorer.html', label: 'Explorer' },
  { href: 'projects.html', label: 'Projects' },
  { href: 'events.html',   label: 'Events'   },
  { href: 'makers.html',   label: 'Makers'   },
  { href: 'store.html',    label: 'Store'    },
];

async function renderNav(activePage = '') {
  const el = document.getElementById('mainNav');
  if (!el) return;

  const user    = await Auth.getUser();
  const current = activePage || location.pathname.split('/').pop();

  const links = NAV_LINKS.map(l =>
    `<a href="${l.href}" class="${current === l.href ? 'active' : ''}">${l.label}</a>`
  ).join('');

  const authBtn = user
    ? `<a href="dashboard.html" class="btn btn-primary btn-sm">Dashboard</a>`
    : `<a href="auth.html"      class="btn btn-primary btn-sm">Login</a>`;

  el.innerHTML = `
    <div class="nav-inner">
      <a href="index.html" class="nav-brand">
        <div class="brand-dot"></div>
        <span class="brand-txt">PARAM</span><span class="brand-acc">.MKRSADDA</span>
      </a>
      <div class="nav-links" id="navLinks">${links}</div>
      <div class="nav-actions">
        ${authBtn}
        <button class="nav-toggle" onclick="document.getElementById('navLinks').classList.toggle('open')">☰</button>
      </div>
    </div>`;
}

function renderFooter() {
  const el = document.getElementById('mainFooter');
  if (!el) return;
  el.innerHTML = `
    <div class="container">
      <div class="grid-4">
        <div>
          <div class="footer-brand">PARAM<span>.MKRSADDA</span></div>
          <div class="footer-tagline">// Bengaluru's Maker Adda</div>
          <p class="text-sm mt-3" style="opacity:0.45;">From curiosity to contribution — your space to learn, build &amp; grow.</p>
        </div>
        <div>
          <div class="footer-links">
            <h5>Learn</h5>
            <a href="explorer.html">Explorer Hub</a>
            <a href="projects.html">Projects</a>
          </div>
        </div>
        <div>
          <div class="footer-links">
            <h5>Community</h5>
            <a href="events.html">Events</a>
            <a href="makers.html">Makers</a>
            <a href="store.html">Store</a>
          </div>
        </div>
        <div>
          <div class="footer-links">
            <h5>Account</h5>
            <a href="auth.html">Login / Sign Up</a>
            <a href="dashboard.html">Dashboard</a>
          </div>
        </div>
      </div>
      <div class="footer-bottom">
        <p>© 2025 Param Innovation Lab · Bengaluru, Bharat</p>
        <p>parammakerspace.in</p>
      </div>
    </div>`;
}
