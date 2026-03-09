/* ================================================
   PARAM MAKERSADDA — Dashboard Sidebar Renderer
   ================================================ */

const TIERS      = ['Curious','Tinkerer','Builder','Maker','Innovator','Lab Pro'];
const TIER_BADGE = ['badge-grey','badge-orange','badge-indigo','badge-teal','badge-orange','badge-green'];

function renderSidebar(activePage, profile, user) {
  const el = document.getElementById('mainSidebar');
  if (!el) return;

  const name   = profile?.full_name || user?.user_metadata?.full_name || 'Maker';
  const handle = profile?.public_url_slug || user?.email?.split('@')[0] || 'maker';
  const tier   = profile?.tier_level ?? 0;

  const links = [
    { key:'overview',              href:'dashboard.html',             label:'Overview' },
    { key:'learning',              href:'dashboard-learning.html',    label:'My Learning' },
    { key:'projects',              href:'dashboard-projects.html',    label:'My Projects' },
    { key:'events',                href:'dashboard-events.html',      label:'My Events' },
    { key:'credentials',           href:'dashboard-credentials.html', label:'Credentials' },
  ];

  const nav = links.map(l =>
    `<a href="${l.href}" class="${activePage === l.key ? 'active' : ''}">${l.label}</a>`
  ).join('');

  el.innerHTML = `
    <div class="sidebar-user">
      <div class="avatar avatar-lg">${getInitials(name)}</div>
      <div class="s-name">${name}</div>
      <div class="s-handle">@${handle}</div>
      <div class="mt-2"><span class="badge ${TIER_BADGE[tier]}">${TIERS[tier]}</span></div>
    </div>
    <nav class="sidebar-nav">
      <div class="nav-group-label">Dashboard</div>
      ${nav}
      <div class="nav-group-label">Account</div>
      <a href="dashboard-profile.html" class="${activePage==='profile'?'active':''}">Edit Profile</a>
      <a href="#" onclick="Auth.signOut();return false;">Logout</a>
    </nav>`;
}
