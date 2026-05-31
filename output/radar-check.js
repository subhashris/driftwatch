
// -- State 
let state = {
  owner: 'jellyfin',
  repo: 'jellyfin-web',
  data: null,
  jobId: null,
  scanMode: 'fast',
};

function setDemoRepo(owner, repo) {
  const input = document.getElementById('repoInput');
  const homeInput = document.getElementById('homeRepoInput');
  if (input) {
    input.value = owner + '/' + repo;
    input.focus();
  }
  if (homeInput) homeInput.value = owner + '/' + repo;
  state.owner = owner;
  state.repo = repo;
  window.currentData = { owner, repo, scan: [], sweep: {}, ownership: [] };
  if (typeof window.initWatchOnNav === 'function') window.initWatchOnNav();
}

function syncRepoInputs(value) {
  const top = document.getElementById('repoInput');
  const home = document.getElementById('homeRepoInput');
  if (top) top.value = value;
  if (home) home.value = value;
}

function hideLaunch() {
  const launch = document.getElementById('launchScreen');
  if (launch) launch.classList.add('hidden');
  document.body.classList.remove('launch-active');
}

function startMode(mode) {
  const homeInput = document.getElementById('homeRepoInput');
  const topInput = document.getElementById('repoInput');
  const value = (homeInput?.value || topInput?.value || '').trim();
  syncRepoInputs(value);
  state.scanMode = mode === 'deep' ? 'deep' : 'fast';
  return startScan({ preventDefault() {} });
}

async function setSail() {
  hideToast();
  const homeInput = document.getElementById('homeRepoInput');
  const topInput = document.getElementById('repoInput');
  const value = (homeInput?.value || topInput?.value || 'jellyfin/jellyfin-web').trim();
  const [owner, repo] = value.split('/');
  if (!owner || !repo) {
    showToast('Enter a repo as owner/repo before setting sail.');
    return;
  }

  syncRepoInputs(`${owner}/${repo}`);
  state.owner = owner;
  state.repo = repo;
  hideLaunch();
  showScreen('askwatch', document.getElementById('navAskWatch'));
  setLiveStatus('LIVE CORAL · loading latest scan snapshot…');

  try {
    const data = await fetchResults(owner, repo, false);
    state.data = data;
    state.owner = data.owner || owner;
    state.repo = data.repo || repo;
    syncRepoInputs(`${state.owner}/${state.repo}`);
    renderAll();
    showScreen('askwatch', document.getElementById('navAskWatch'));
    setLiveStatus(`LIVE CORAL · latest scan · ${new Date().toLocaleTimeString()}`);
  } catch (e) {
    window.currentData = { owner, repo, scan: [], sweep: {}, ownership: [] };
    setLiveStatus('LIVE CORAL · no latest scan loaded');
    showToast('No latest scan results found for this repo yet. Use Chart Course once, then Set Sail will open the latest snapshot.');
  }
}

// -- Navigation 
function showScreen(target, navItem) {
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  if (navItem) navItem.classList.add('active');
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  const screenId = target === 'askwatch' ? 'screenAskWatch' : 'screen-' + target;
  const screenEl = document.getElementById(screenId);
  if (screenEl) screenEl.classList.add('active');
  if (target === 'patchlag' && typeof renderThreatIntel === 'function') renderThreatIntel();
  if (target === 'overview' && window.currentData && typeof renderOverview === 'function') {
    renderOverview(window.currentData);
  }
  if (target === 'askwatch' && typeof window.initWatchOnNav === 'function') window.initWatchOnNav();
  window.scrollTo({ top: 0, behavior: 'instant' });
}

document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', () => {
    const target = item.id === 'navAskWatch' ? 'askwatch' : item.dataset.screen;
    if (target) showScreen(target, item);
  });
});

// -- Helpers 
function bandForDays(d) {
  if (d > 365) return 'red';
  if (d > 90) return 'amber';
  if (d > 30) return 'blue';
  return 'dim';
}
function tideColor(d) {
  if (d > 365) return 'red';
  if (d > 90) return 'amber';
  if (d > 30) return 'blue';
  return 'green';
}
function escape(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => (
    {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]
  ));
}
function filterBots(owners) {
  return (owners || []).filter(o => !/\[bot\]/i.test(o));
}
function isPreCve(pkgName, sweep) {
  if (!sweep || !Array.isArray(sweep.pre_cve_findings)) return false;
  return sweep.pre_cve_findings.some(f => f.name === pkgName && f.has_security_deprecation);
}
function actionabilityForPackage(pkgName, sweep) {
  if (!sweep || !Array.isArray(sweep.upgrade_actionability)) return null;
  const rows = sweep.upgrade_actionability.filter(u => u.name === pkgName);
  if (!rows.length) return null;
  // Pick the "most severe" actionability: NO_FIX > BREAKING > MODERATE > SAFE
  const order = { 'NO_FIX': 4, 'BREAKING': 3, 'MODERATE': 2, 'SAFE': 1 };
  rows.sort((a, b) => (order[b.actionability]||0) - (order[a.actionability]||0));
  return rows[0].actionability;
}
function ownerForPackage(pkgName, ownership) {
  if (!Array.isArray(ownership)) return [];
  const row = ownership.find(o => o.package === pkgName);
  return row ? filterBots(row.owners) : [];
}
function computeUrgency(pkg, sweep) {
  const days = pkg.worst_days_exposed || 0;
  const cves = (pkg.cves || []).length;
  const act = actionabilityForPackage(pkg.name, sweep);
  const breaking = act === 'BREAKING' ? 10 : 0;
  const pre = isPreCve(pkg.name, sweep) ? 10 : 0;
  const score = Math.min(100, Math.round(
    (days / 2090) * 60 +
    (cves / 7) * 25 +
    breaking +
    pre
  ));
  return score;
}
function urgencyBand(score) {
  if (score >= 80) return 'red';
  if (score >= 60) return 'amber';
  if (score >= 40) return 'blue';
  return 'dim';
}
function urgencyVerdict(score) {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 40) return 'MEDIUM';
  return 'LOW';
}

// -- Data fetch 
async function fetchResults(owner, repo, demo = false) {
  const url = `/api/results/${owner}/${repo}${demo ? '?demo=true' : ''}`;
  const r = await fetch(url);
  if (!r.ok) {
    let detail = '';
    try {
      const body = await r.json();
      detail = typeof body.detail === 'string'
        ? body.detail
        : (body.detail?.message || JSON.stringify(body.detail));
    } catch (e) {
      detail = r.statusText;
    }
    throw new Error(`HTTP ${r.status}: ${detail || r.statusText}`);
  }
  return await r.json();
}

async function loadDemo() {
  hideToast();
  setLiveStatus('SAMPLE DATA · loading bundled sample…');
  try {
    const data = await fetchResults('jellyfin', 'jellyfin-web', true);
    state.data = data;
    state.owner = data.owner;
    state.repo = data.repo;
    renderAll();
    setLiveStatus(`SAMPLE DATA · bundled Coral snapshot · ${new Date().toLocaleTimeString()}`);
  } catch (e) {
    showToast('Failed to load sample: ' + e.message);
  }
}

// -- Renderers 
function renderAll() {
  const d = state.data;
  if (!d) return;
  window.currentData = d;
  renderOverview(d);
  renderPatchLag(d);
  renderPreCve(d);
  renderMaintainer(d);
  renderOrders(d);
  renderCrew(d);
  renderQueries(d);
  updateBadges(d);
  const meta = d.scan_meta || {};
  const scanned = meta.packages_scanned;
  const total = meta.sbom_packages_total;
  const mode = meta.mode || 'scan';
  const scanScope = scanned && total
    ? `${scanned} of ${total} SBOM packages scanned`
    : `${d.scan?.length || 0} vulnerable packages`;
  document.getElementById('overviewSub').textContent = `${d.owner}/${d.repo} — ${mode} · ${scanScope}`;
  const sourceKind = d.sources?.scan_kind || 'scan snapshot';
  const completedStages = Object.entries(meta.stages || {})
    .map(([stage, status]) => `${stage}:${status}`)
    .join(', ');
  document.getElementById('footerNote').textContent = `${d.scan?.length || 0} vulnerable packages · ${d.sweep?.upgrade_actionability?.length || 0} upgrade paths · ${d.ownership?.length || 0} owners mapped · ${sourceKind} · ${completedStages || 'stages unavailable'} · ${meta.scan_completed_at || d.sweep?.scan_date || 'no timestamp'}`;
}

function updateBadges(d) {
  const scan = d.scan || [];
  const sweep = d.sweep || {};
  const ua = sweep.upgrade_actionability || [];
  const preCount = (sweep.pre_cve_findings || []).filter(f => f.has_security_deprecation).length;
  const safeDedupe = new Set(ua.filter(u => u.actionability === 'SAFE').map(u => u.name));
  const badgeOv = document.getElementById('badge-overview');
  if (badgeOv) { badgeOv.textContent = scan.length; badgeOv.className = 'nav-badge ' + (scan.length > 0 ? 'red' : 'green'); }
  const badgePl = document.getElementById('badge-patchlag');
  if (badgePl) badgePl.textContent = scan.length;
  const badgeCr = document.getElementById('badge-crew');
  if (badgeCr) badgeCr.textContent = (d.ownership || []).length;
}

function renderOverview(d) {
  const scan = (d.scan || []).slice().sort((a, b) => (b.worst_days_exposed || 0) - (a.worst_days_exposed || 0));
  const sweep = d.sweep || {};
  const ua = sweep.upgrade_actionability || [];
  const worst = scan[0];
  const preCount = (sweep.pre_cve_findings || []).filter(f => f.has_security_deprecation).length;

  // Hero — weeks primary, days secondary, dynamic comparison
  const headlineEl = document.getElementById('headline');
  if (worst) {
    const worstDays = worst.worst_days_exposed || 0;
    const worstWeeks = Math.round(worstDays / 7);
    // Earliest CVE published date for the worst package
    let earliestPub = null;
    (worst.cves || []).forEach(c => {
      if (!c.published) return;
      const dt = new Date(c.published);
      if (!isNaN(dt) && (!earliestPub || dt < earliestPub)) earliestPub = dt;
    });
    const fixDateStr = earliestPub
      ? earliestPub.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })
      : 'before this scan began';

    headlineEl.innerHTML = `
      <div class="cb-hero">
        <div class="cb-hero-numwrap">
          <span class="cb-hero-weeks gold-metal" id="cb-hero-weeks-num" data-target="${worstWeeks}">0</span>
          <span class="cb-hero-weeks-unit">weeks</span>
        </div>
        <div class="cb-hero-days-line">
          <span class="cb-hero-days-num" id="cb-hero-days-num" data-target="${worstDays}">0</span> days
        </div>
        <div class="cb-hero-sub">
          That's how long <span class="cb-hero-repo">${escape(d.owner)}/${escape(d.repo)}</span> has been exposed to
          <span class="cb-hero-pkg">${escape(worst.name)}</span>'s vulnerability &mdash;
          with a fix available since <span class="cb-hero-fix-date">${escape(fixDateStr)}</span>.
        </div>
      </div>
    `;
    animateCountUp(document.getElementById('cb-hero-weeks-num'), worstWeeks, 2000);
    animateCountUp(document.getElementById('cb-hero-days-num'), worstDays, 2000);
  } else {
    headlineEl.innerHTML = `
      <div class="cb-hero">
        <div class="cb-hero-sub">
          <span style="color:var(--text);font-weight:500">No vulnerable packages detected — clean waters ahead.</span>
        </div>
      </div>
    `;
  }

  // Severity-weighted 4-panel stats — deduplicate scan by name first
  const _seenForTiles = new Set();
  const _dedupedScan = scan.filter(p => { if (_seenForTiles.has(p.name)) return false; _seenForTiles.add(p.name); return true; });
  const vulnCount = _dedupedScan.length;
  const breakingCount = _dedupedScan.filter(p => {
    const u = ua.find(x => x.name === p.name);
    return u && u.actionability === 'BREAKING';
  }).length;
  const safeCount = _dedupedScan.filter(p => {
    const u = ua.find(x => x.name === p.name);
    return u && u.actionability === 'SAFE';
  }).length;

  const statsRow = document.getElementById('statsRow');
  statsRow.className = 'cb-stats';
  statsRow.innerHTML = `
    <div class="cb-stat s-red">
      <div class="cb-stat-label">Vulnerable Packages</div>
      <div class="cb-stat-value" data-target="${vulnCount}">0</div>
      <div class="cb-stat-sub">across all ecosystems</div>
    </div>
    <div class="cb-stat s-orange">
      <div class="cb-stat-label">Pre-CVE Signals</div>
      <div class="cb-stat-value" data-target="${preCount}">0</div>
    </div>
    <div class="cb-stat s-orange">
      <div class="cb-stat-label">Critical Upgrades</div>
      <div class="cb-stat-value" data-target="${breakingCount}">0</div>
    </div>
    <div class="cb-stat s-green">
      <div class="cb-stat-label">Safe Upgrades</div>
      <div class="cb-stat-value" data-target="${safeCount}">0</div>
    </div>
  `;
  statsRow.querySelectorAll('.cb-stat-value').forEach(el => {
    animateCountUp(el, parseInt(el.dataset.target, 10), 1500);
  });

  // Expose sweep data globally so the chart builder can reach it
  window._sweepData = sweep;

  buildHazardChart(scan, d.ownership || []);
  buildParchmentScrolls(scan, sweep);
}

function buildParchmentScrolls(scanData, sweepData) {
  // Pull directly from scan — deduplicate by name, join with ua.find (same logic as tiles)
  const ua = sweepData?.upgrade_actionability || [];
  const seen = new Set();
  const breaking = [], safe = [];
  (scanData || []).forEach(pkg => {
    if (seen.has(pkg.name)) return;
    seen.add(pkg.name);
    const u = ua.find(x => x.name === pkg.name);
    if (!u) return;
    const entry = { name: pkg.name, days: pkg.worst_days_exposed || 0 };
    if (u.actionability === 'BREAKING') breaking.push(entry);
    else if (u.actionability === 'SAFE') safe.push(entry);
  });
  breaking.sort((a, b) => b.days - a.days);
  safe.sort((a, b) => b.days - a.days);

  const renderRow = (e) => {
    const weeks = Math.round((e.days || 0) / 7);
    return `<div class="cb-scroll-row">
      <span class="cb-scroll-pkg" title="${escape(e.name)}">${escape(e.name)}</span>
      <span class="cb-scroll-weeks">${weeks.toLocaleString()} weeks exposed</span>
    </div>`;
  };
  const renderList = (arr) => {
    if (!arr.length) return '<div class="cb-scroll-empty">&mdash; no entries &mdash;</div>';
    const top = arr.slice(0, 6).map(renderRow).join('');
    const more = arr.length > 6
      ? `<div class="cb-scroll-more">+ ${arr.length - 6} more</div>`
      : '';
    return top + more;
  };

  const stormList = document.getElementById('cb-storm-list');
  const smoothList = document.getElementById('cb-smooth-list');
  if (stormList) stormList.innerHTML = renderList(breaking);
  if (smoothList) smoothList.innerHTML = renderList(safe);
}

// -- Hazard Chart (2D scatter of buoys) 
function buildHazardChart(scanData, ownershipData) {
  const chart = document.getElementById('hazard-chart');
  if (!chart) return;
  chart.querySelectorAll('.hazard-buoy').forEach(b => b.remove());

  const chartW = chart.offsetWidth || 800;
  const chartH = chart.offsetHeight || 340;
  const padding = { left: 40, right: 40, top: 30, bottom: 40 };
  const innerW = chartW - padding.left - padding.right;
  const innerH = chartH - padding.top - padding.bottom;

  // Deduplicate by package name
  const packages = [];
  const seen = new Set();
  scanData.forEach(pkg => {
    if (!seen.has(pkg.name)) { seen.add(pkg.name); packages.push(pkg); }
  });
  if (!packages.length) return;

  const maxDays = Math.max(2090, ...packages.map(p => p.worst_days_exposed || 0));
  const maxCVEs = Math.max(1, ...packages.map(p => (p.cves || []).length));

  const sweep = window._sweepData || {};
  const upgradeByName = {};
  (sweep.upgrade_actionability || []).forEach(u => {
    if (!upgradeByName[u.name] || (u.days_exposed || 0) > (upgradeByName[u.name].days_exposed || 0)) {
      upgradeByName[u.name] = u;
    }
  });

  packages.forEach((pkg, i) => {
    const xRatio = Math.min((pkg.worst_days_exposed || 0) / maxDays, 1);
    const yRatio = 1 - Math.min((pkg.cves || []).length / maxCVEs, 1);
    const jitter = (val, seed) => val + (Math.sin(seed * 127.1) * 0.04);
    const x = padding.left + Math.max(0, Math.min(1, jitter(xRatio, i))) * innerW;
    const y = padding.top + Math.max(0, Math.min(1, jitter(yRatio, i + 7))) * innerH;

    const size = 16 + Math.min((pkg.cves || []).length * 5, 24);

    const upgrade = upgradeByName[pkg.name];
    const actionability = upgrade?.actionability || 'BREAKING';
    const preCVE = (sweep.pre_cve_findings || [])
      .find(f => f.name === pkg.name && f.has_security_deprecation);

    // Dot color must match the legend exactly (FIX 3):
    //   BREAKING -> red, SAFE -> green, pre-CVE -> cyan.
    //   Mixed (BREAKING + pre-CVE) -> red dot with a cyan secondary ring.
    let color, glowColor, ringColor;
    if (preCVE && actionability === 'BREAKING') {
      color = '#FF4444'; glowColor = 'rgba(255,68,68,0.5)'; ringColor = '#00FFFF';
    } else if (preCVE) {
      color = '#00FFFF'; glowColor = 'rgba(0,255,255,0.5)'; ringColor = '#00FFFF';
    } else if (actionability === 'SAFE') {
      color = '#00FF88'; glowColor = 'rgba(0,255,136,0.5)'; ringColor = '#00FF88';
    } else {
      color = '#FF4444'; glowColor = 'rgba(255,68,68,0.5)'; ringColor = '#FF4444';
    }

    const ownerRecord = (ownershipData || []).find(o => o.package === pkg.name);
    const owner = ownerRecord?.owners?.find(o => !/\[bot\]/i.test(o));

    const buoy = document.createElement('div');
    buoy.className = 'hazard-buoy';
    buoy.dataset.pkgName = pkg.name;
    buoy.style.left = x + 'px';
    buoy.style.top = y + 'px';
    buoy.innerHTML = `
      <div class="buoy-ring" style="
        width: ${size}px; height: ${size}px;
        background: radial-gradient(circle, ${color}33 0%, ${color}11 100%);
        border: 2px solid ${color};
        box-shadow: 0 0 ${size/2}px ${glowColor}, inset 0 0 ${size/3}px ${color}22;
      ">
        <div style="
          width: ${size*0.35}px; height: ${size*0.35}px;
          border-radius: 50%;
          background: ${color};
          box-shadow: 0 0 8px ${color};
        "></div>
      </div>
      <div style="position:absolute;inset:-4px;border-radius:50%;
        border: 1px solid ${ringColor}${ringColor === color ? '44' : 'cc'}; animation: buoyPulse ${2 + (i*0.3)%3}s ease-out infinite;"></div>
      <div class="buoy-label">${escape(pkg.name.split('/').pop().substring(0, 14))}</div>
    `;

    buoy.addEventListener('mouseenter', (e) => {
      const rank = buoy.dataset.rank;

      let rankBadge = buoy.querySelector('.rank-badge');
      if (!rankBadge) {
        rankBadge = document.createElement('div');
        rankBadge.className = 'rank-badge';
        buoy.appendChild(rankBadge);
      }
      rankBadge.textContent = rank ? '#' + rank : '';
      rankBadge.style.display = rank ? 'flex' : 'none';

      const tt = document.getElementById('chart-tooltip');
      if (!tt) return;
      const rankLine = rank
        ? `<div class="tooltip-rank">Priority #${rank} of 10 most critical</div>`
        : '';
      document.getElementById('tt-pkg').innerHTML =
        rankLine + '<span style="color:var(--text)">' +
        escape(pkg.name + '@' + (pkg.version || '?')) + '</span>';
      document.getElementById('tt-days').textContent = (pkg.worst_days_exposed || 0).toLocaleString() + ' days exposed';
      document.getElementById('tt-owner').textContent = owner ? '@' + owner : 'owner unknown';
      const fixedIn = upgrade?.fixed_version || pkg.cves?.[0]?.fixed_in || '?';
      document.getElementById('tt-action').innerHTML = '<span style="color:' + color + '">' + actionability + '</span> &middot; fix in ' + escape(fixedIn);
      const cveCount = (pkg.cves || []).length;
      document.getElementById('tt-cves').textContent = cveCount + ' CVE' + (cveCount === 1 ? '' : 's') + (preCVE ? ' · PRE-CVE signal' : '');
      const rect = chart.getBoundingClientRect();
      const ex = e.clientX - rect.left;
      const ey = e.clientY - rect.top;
      tt.style.left = Math.min(ex + size + 10, chartW - 220) + 'px';
      tt.style.top = Math.min(Math.max(ey - 20, 4), chartH - 130) + 'px';
      tt.style.display = 'block';
    });

    buoy.addEventListener('mouseleave', () => {
      const rankBadge = buoy.querySelector('.rank-badge');
      if (rankBadge) rankBadge.style.display = 'none';
      const tt = document.getElementById('chart-tooltip');
      if (tt) tt.style.display = 'none';
    });

    chart.appendChild(buoy);
  });

  // Draw severity chain after buoys are placed
  setTimeout(() => {
    const deduped = [];
    const seenNames = new Set();
    packages.forEach(pkg => {
      if (!seenNames.has(pkg.name)) {
        seenNames.add(pkg.name);
        deduped.push(pkg);
      }
    });
    drawSeverityChain(deduped, chart);
  }, 50);
}

function drawSeverityChain(packages, chart) {
  const existing = chart.querySelector('.severity-chain-svg');
  if (existing) existing.remove();

  const chartW = chart.offsetWidth || 800;
  const chartH = chart.offsetHeight || 340;

  const scored = packages.map(pkg => {
    const score = Math.min(100, Math.round(
      (pkg.worst_days_exposed / 2090 * 60) +
      (pkg.cves.length / 7 * 25)
    ));
    return { ...pkg, _urgency: score };
  });
  scored.sort((a, b) => b._urgency - a._urgency);
  const top10 = scored.slice(0, 10);

  const buoyEls = chart.querySelectorAll('.hazard-buoy');
  const buoyPositions = {};
  buoyEls.forEach(el => {
    const name = el.dataset.pkgName;
    if (name) {
      buoyPositions[name] = {
        x: parseFloat(el.style.left),
        y: parseFloat(el.style.top)
      };
    }
  });

  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', 'severity-chain-svg');
  svg.setAttribute('width', chartW);
  svg.setAttribute('height', chartH);
  svg.style.cssText = 'position:absolute;top:0;left:0;pointer-events:none;z-index:1;';

  for (let i = 0; i < top10.length - 1; i++) {
    const a = buoyPositions[top10[i].name];
    const b = buoyPositions[top10[i + 1].name];
    if (!a || !b) continue;

    const opacity = 0.6 - (i * 0.04);
    const color = i < 3 ? '#FF4444' : i < 6 ? '#FF8C00' : '#E8C55A';

    const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    line.setAttribute('x1', a.x);
    line.setAttribute('y1', a.y);
    line.setAttribute('x2', b.x);
    line.setAttribute('y2', b.y);
    line.setAttribute('stroke', color);
    line.setAttribute('stroke-width', '1.5');
    line.setAttribute('stroke-dasharray', '5 6');
    line.setAttribute('stroke-opacity', opacity);
    line.style.filter = `drop-shadow(0 0 3px ${color})`;

    svg.appendChild(line);
  }

  chart.insertBefore(svg, chart.firstChild);

  top10.forEach((pkg, rank) => {
    const buoyEl = chart.querySelector(`.hazard-buoy[data-pkg-name="${pkg.name}"]`);
    if (buoyEl) {
      buoyEl.dataset.rank = rank + 1;
    }
  });
}

// -- Three Action Columns 
function buildActionColumns(scanData, ownershipData, sweepData) {
  const upgradeMap = {};
  (sweepData?.upgrade_actionability || []).forEach(u => {
    if (!upgradeMap[u.name] || (u.days_exposed || 0) > (upgradeMap[u.name].days_exposed || 0)) {
      upgradeMap[u.name] = u;
    }
  });

  const actNow = [], thisSprint = [], watch = [];
  const seen = new Set();
  scanData.forEach(pkg => {
    if (seen.has(pkg.name)) return;
    seen.add(pkg.name);
    const upgrade = upgradeMap[pkg.name];
    const ownerRow = (ownershipData || []).find(o => o.package === pkg.name);
    const ownerName = ownerRow?.owners?.find(o => !/\[bot\]/i.test(o));
    const preCVE = (sweepData?.pre_cve_findings || [])
      .find(f => f.name === pkg.name && f.has_security_deprecation);
    const item = { pkg, upgrade, ownerName, preCVE };
    if (preCVE) watch.push(item);
    else if (upgrade?.actionability === 'SAFE') thisSprint.push(item);
    else if ((pkg.worst_days_exposed || 0) > 90) actNow.push(item);
    else watch.push(item);
  });

  actNow.sort((a, b) => (b.pkg.worst_days_exposed || 0) - (a.pkg.worst_days_exposed || 0));
  thisSprint.sort((a, b) => (b.pkg.worst_days_exposed || 0) - (a.pkg.worst_days_exposed || 0));
  watch.sort((a, b) => (b.pkg.worst_days_exposed || 0) - (a.pkg.worst_days_exposed || 0));

  function renderItem(item, accent) {
    const { pkg, upgrade, ownerName, preCVE } = item;
    const daysStr = (pkg.worst_days_exposed || 0).toLocaleString() + 'd';
    const fixVer = upgrade?.fixed_version || pkg.cves?.[0]?.fixed_in;
    const fixStr = fixVer ? ` → ${escape(fixVer)}` : '';
    return `
      <div class="action-item">
        <div class="action-item-pkg">${escape(pkg.name.split('/').pop())}</div>
        <div class="action-item-meta">
          <span style="color:${accent}">${daysStr}</span>
          ${fixStr ? `<span style="color:var(--text3)"> · fix${fixStr}</span>` : ''}
          ${preCVE ? '<span style="color:var(--neon-cyan)"> · ⚡ PRE-CVE</span>' : ''}
        </div>
        ${ownerName ? `<div class="action-item-owner">@${escape(ownerName)}</div>` : ''}
      </div>`;
  }

  const empty = (msg) => `<div style="padding:12px;font-size:11px;color:var(--text3)">${msg}</div>`;
  const actNowBody = document.getElementById('act-now-body');
  const sprintBody = document.getElementById('sprint-body');
  const watchBody = document.getElementById('watch-body');
  if (actNowBody) actNowBody.innerHTML = actNow.length ? actNow.map(i => renderItem(i, 'var(--neon-red)')).join('') : empty('All hands safe — no critical threats');
  if (sprintBody) sprintBody.innerHTML = thisSprint.length ? thisSprint.map(i => renderItem(i, 'var(--neon-green)')).join('') : empty('No safe upgrades available');
  if (watchBody) watchBody.innerHTML = watch.length ? watch.map(i => renderItem(i, 'var(--neon-cyan)')).join('') : empty('Clear skies — no pre-CVE signals detected');

  const acn = document.getElementById('act-now-count'); if (acn) acn.textContent = actNow.length;
  const spc = document.getElementById('sprint-count'); if (spc) spc.textContent = thisSprint.length;
  const wac = document.getElementById('watch-count'); if (wac) wac.textContent = watch.length;
}

function renderThreatIntelLegacy(data) {
  const d = data || window.currentData;
  const screen = document.getElementById('screen-patchlag');
  if (!screen) return;

  screen.innerHTML = `
    <style>
      .ti-kicker { font-family: var(--mono); font-size: 11px; letter-spacing: 3px; color: var(--gold); margin: 0 0 4px; text-transform: uppercase; }
      .ti-subtitle { color: var(--text2); font-size: 14px; margin: 6px 0 0; }
      .ti-divider { width: 100%; max-width: 600px; height: 30px; margin: 12px 0 24px; display: block; }
      .ti-panels { display: grid; grid-template-columns: 2fr 1.5fr 1.5fr; gap: 20px; align-items: stretch; }
      .ti-panel { min-height: 520px; background: linear-gradient(180deg, #0d1e30 0%, #0a1a28 100%); border: 1px solid rgba(200,168,75,0.2); border-radius: 8px; overflow: hidden; position: relative; display: flex; flex-direction: column; }
      .ti-panel + .ti-panel::before { content: ''; position: absolute; left: 0; top: 0; bottom: 0; width: 3px; background: linear-gradient(180deg, transparent, rgba(200,168,75,0.4), rgba(200,168,75,0.2), rgba(200,168,75,0.4), transparent); pointer-events: none; }
      .ti-panel-header { padding: 16px 20px 12px; border-bottom: 1px solid rgba(200,168,75,0.15); display: flex; align-items: center; gap: 10px; }
      .ti-panel-label { font-family: var(--mono); font-size: 10px; letter-spacing: 2px; text-transform: uppercase; color: var(--gold); }
      .ti-panel-body { flex: 1; position: relative; }
      .ti-hazards-body { padding: 20px 16px; }
      .ti-flag-scroll { width: 100%; overflow-x: auto; overflow-y: hidden; }
      .ti-flags-svg { display: block; min-width: 100%; }
      .ti-seafloor { width: 100%; height: 20px; margin-bottom: 8px; }
      .ti-legend { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-top: 12px; font-family: var(--mono); font-size: 9px; color: var(--text2); }
      .ti-legend-item { display: inline-flex; align-items: center; gap: 5px; }
      .ti-pennant { width: 0; height: 0; border-top: 5px solid transparent; border-bottom: 5px solid transparent; border-left: 10px solid currentColor; }
      .ti-radar-body { padding: 16px; overflow: hidden; }
      .ti-radar-bg { position: absolute; inset: 0; width: 100%; height: 100%; pointer-events: none; opacity: 0.8; }
      .ti-radar-sweep { transform-origin: 150px 150px; animation: radarSpin 6s linear infinite; }
      @keyframes radarSpin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      .ti-weather-list { position: relative; z-index: 1; }
      .ti-weather-row { display: flex; align-items: center; gap: 10px; padding: 8px 4px; border-bottom: 1px solid rgba(255,255,255,0.04); }
      .ti-weather-main { min-width: 0; flex: 1; }
      .ti-weather-pkg { color: var(--gold); font-family: var(--mono); font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
      .ti-weather-speed { font-family: var(--mono); font-size: 9px; }
      .ti-weather-verdict { color: var(--text3); font-family: var(--mono); font-size: 9px; text-align: right; max-width: 90px; }
      .ti-orders-body { padding: 16px; font-family: var(--mono); }
      .ti-section-header { display: flex; align-items: center; gap: 8px; padding: 10px 0 8px; font-size: 10px; letter-spacing: 2px; text-transform: uppercase; }
      .ti-safe { color: var(--neon-green); }
      .ti-breaking { color: var(--neon-red); }
      .ti-section-sub { font-size: 9px; opacity: 0.6; letter-spacing: 1px; margin-left: 4px; }
      .ti-log-entry { display: flex; align-items: center; gap: 6px; padding: 7px 4px; border-bottom: 1px solid rgba(255,255,255,0.04); font-size: 11px; }
      .ti-log-entry:hover { background: rgba(255,255,255,0.02); }
      .ti-log-badge { font-size: 9px; padding: 2px 5px; border-radius: 3px; flex-shrink: 0; }
      .ti-badge-safe { background: rgba(0,255,136,0.1); border: 1px solid var(--neon-green); color: var(--neon-green); }
      .ti-badge-breaking { background: rgba(255,68,68,0.1); border: 1px solid var(--neon-red); color: var(--neon-red); }
      .ti-log-pkg { color: var(--gold); flex-shrink: 0; max-width: 90px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
      .ti-log-arrow { color: var(--text3); }
      .ti-log-fix { color: var(--neon-cyan); flex-shrink: 0; }
      .ti-log-days { margin-left: auto; color: var(--text2); flex-shrink: 0; }
      .ti-days-red { color: var(--neon-red); }
      .ti-rope { width: 100%; height: 16px; margin: 12px 0; }
      .ti-empty { min-height: 520px; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 14px; color: var(--text2); font-family: var(--mono); }
    </style>
    <div class="screen-header">
      <p class="ti-kicker">THREAT INTELLIGENCE</p>
      <h1 class="screen-sub">The Navigator's Chart</h1>
      <p class="ti-subtitle">Every hazard plotted. Every storm forecast. Orders written in the captain's log.</p>
      <svg viewBox="0 0 600 30" class="ti-divider" xmlns="http://www.w3.org/2000/svg">
        <line x1="0" y1="15" x2="255" y2="15" stroke="rgba(200,168,75,0.3)" stroke-width="1"/>
        <line x1="345" y1="15" x2="600" y2="15" stroke="rgba(200,168,75,0.3)" stroke-width="1"/>
        <circle cx="300" cy="15" r="12" fill="none" stroke="rgba(200,168,75,0.4)" stroke-width="1"/>
        <polygon points="300,3 303,13 300,11 297,13" fill="rgba(200,168,75,0.7)"/>
        <polygon points="300,27 303,17 300,19 297,17" fill="rgba(200,168,75,0.4)"/>
        <polygon points="288,15 298,12 296,15 298,18" fill="rgba(200,168,75,0.4)"/>
        <polygon points="312,15 302,12 304,15 302,18" fill="rgba(200,168,75,0.7)"/>
        <circle cx="300" cy="15" r="2" fill="rgba(200,168,75,0.8)"/>
      </svg>
    </div>
    <div id="threatIntelRoot"></div>
  `;

  const root = document.getElementById('threatIntelRoot');
  if (!window.currentData || !window.currentData.scan) {
    root.innerHTML = `<div class="ti-empty">
      <svg viewBox="0 0 16 20" width="28" height="34" xmlns="http://www.w3.org/2000/svg">
        <circle cx="8" cy="4" r="3" fill="none" stroke="var(--gold)" stroke-width="1.2"/>
        <line x1="8" y1="7" x2="8" y2="18" stroke="var(--gold)" stroke-width="1.2"/>
        <path d="M2,11 Q8,14 14,11" fill="none" stroke="var(--gold)" stroke-width="1.2"/>
      </svg>
      <div>No intelligence loaded — chart a course first.</div>
    </div>`;
    return;
  }

  const rawScan = window.currentData.scan || [];
  const ownership = window.currentData.ownership || [];
  const sweep = window.currentData.sweep || {};
  function getFirstOwner(pkgName) {
    const o = ownership.find(x => String(x.package || '').toLowerCase() === String(pkgName || '').toLowerCase());
    return o && o.owners && o.owners[0] ? '@' + o.owners[0] : '';
  }
  const scan = rawScan.map(p => {
    const u = actionabilityForPackage(p.name, sweep);
    const own = ownership.find(x => String(x.package || '').toLowerCase() === String(p.name || '').toLowerCase()) || {};
    return {
      package: p.name,
      version: p.version || '?',
      days_exposed: p.days_exposed || p.worst_days_exposed || 0,
      actionability: u || own.actionability || 'MODERATE',
      fix_version: own.fixed_in || p.fix_version || p.fixed_version || (p.cves && p.cves[0] && p.cves[0].fixed_in) || '?',
      owner: getFirstOwner(p.name)
    };
  }).sort((a, b) => b.days_exposed - a.days_exposed);

  const maxDays = Math.max(1, ...scan.map(p => p.days_exposed));
  const panelWidth = 340;
  const flagCount = scan.length || 1;
  const slotWidth = Math.max(22, Math.floor(panelWidth / flagCount));
  const chartHeight = 200;
  const svgWidth = Math.max(340, flagCount * slotWidth);
  let flagsSVG = `<svg class="ti-flags-svg" viewBox="0 0 ${svgWidth} ${chartHeight + 60}" xmlns="http://www.w3.org/2000/svg">
    <defs><linearGradient id="depthGrad" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="rgba(0,40,80,0.0)"/><stop offset="100%" stop-color="rgba(0,80,120,0.15)"/></linearGradient></defs>
    <rect width="100%" height="${chartHeight}" fill="url(#depthGrad)" rx="4"/>`;
  scan.forEach((pkg, i) => {
    const flagHeight = Math.max(30, Math.round((pkg.days_exposed / maxDays) * 160));
    const x = i * slotWidth + slotWidth / 2;
    const baseY = chartHeight - 10;
    const topY = baseY - flagHeight;
    const color = pkg.actionability === 'BREAKING' ? '#FF4444' : pkg.actionability === 'SAFE' ? '#00FF88' : '#FF8C00';
    const pw = Math.min(18, slotWidth - 2);
    const shortName = pkg.package.length > 8 ? pkg.package.slice(0, 7) + '…' : pkg.package;
    flagsSVG += `<line x1="${x}" y1="${baseY}" x2="${x}" y2="${topY}" stroke="rgba(200,168,75,0.6)" stroke-width="1.5"/>
      <polygon points="${x},${topY} ${x + pw},${topY + pw/2} ${x},${topY + pw}" fill="${color}" opacity="0.85"/>
      <circle cx="${x}" cy="${baseY}" r="2.5" fill="rgba(200,168,75,0.5)"/>
      <text x="${x}" y="${baseY + 14}" font-family="monospace" font-size="7" fill="rgba(200,168,75,0.6)" text-anchor="middle" transform="rotate(45, ${x}, ${baseY + 14})">${escape(shortName)}</text>
      <text x="${x}" y="${topY - 4}" font-family="monospace" font-size="7" fill="${color}" text-anchor="middle" opacity="0.9">${pkg.days_exposed}d</text>`;
  });
  flagsSVG += `<path d="M0,${chartHeight - 8} C60,${chartHeight-12} 120,${chartHeight-4} 180,${chartHeight-8} C240,${chartHeight-12} 300,${chartHeight-4} ${svgWidth},${chartHeight-8}" fill="none" stroke="rgba(0,150,200,0.25)" stroke-width="1.5"/></svg>`;

  const weatherIcons = {
    VERY_SLOW: `<svg viewBox="0 0 24 24" width="24" height="24"><path d="M3,9 Q3,5 7,5 Q8,2 12,2 Q17,2 17,6 Q20,5 21,8 Q23,8 23,10 Q23,13 20,13 L5,13 Q3,13 3,11 Z" fill="none" stroke="#FF4444" stroke-width="1.2"/><polyline points="10,14 8,18 11,18 9,22" fill="none" stroke="#FF8C00" stroke-width="1.5" stroke-linejoin="round"/></svg>`,
    SLOW: `<svg viewBox="0 0 24 24" width="24" height="24"><path d="M4,9 Q4,6 7,6 Q8,3 12,3 Q16,3 16,7 Q19,6 20,9 Q22,9 22,11 Q22,13 19,13 L5,13 Q4,13 4,11 Z" fill="none" stroke="#FF8C00" stroke-width="1.2"/><line x1="8" y1="15" x2="7" y2="18" stroke="#FF8C00" stroke-width="1.2"/><line x1="12" y1="15" x2="11" y2="18" stroke="#FF8C00" stroke-width="1.2"/><line x1="16" y1="15" x2="15" y2="18" stroke="#FF8C00" stroke-width="1.2"/></svg>`,
    MODERATE: `<svg viewBox="0 0 24 24" width="24" height="24"><circle cx="8" cy="14" r="5" fill="none" stroke="#C8A84B" stroke-width="1.2"/><path d="M11,10 Q11,6 15,6 Q19,6 19,10 Q21,10 21,12 Q21,14 18,14 L12,14" fill="none" stroke="var(--text2)" stroke-width="1.2"/></svg>`,
    FAST: `<svg viewBox="0 0 24 24" width="24" height="24"><circle cx="12" cy="12" r="4" fill="none" stroke="#00FF88" stroke-width="1.2"/><line x1="12" y1="2" x2="12" y2="5" stroke="#00FF88" stroke-width="1.2"/><line x1="12" y1="19" x2="12" y2="22" stroke="#00FF88" stroke-width="1.2"/><line x1="2" y1="12" x2="5" y2="12" stroke="#00FF88" stroke-width="1.2"/><line x1="19" y1="12" x2="22" y2="12" stroke="#00FF88" stroke-width="1.2"/><line x1="4.9" y1="4.9" x2="7.1" y2="7.1" stroke="#00FF88" stroke-width="1.2"/><line x1="16.9" y1="16.9" x2="19.1" y2="19.1" stroke="#00FF88" stroke-width="1.2"/></svg>`
  };
  function speedFor(days) { return days > 500 ? 'VERY_SLOW' : days > 150 ? 'SLOW' : days > 60 ? 'MODERATE' : 'FAST'; }
  const speedColor = { VERY_SLOW: 'var(--neon-red)', SLOW: 'var(--neon-orange)', MODERATE: 'var(--gold)', FAST: 'var(--neon-green)' };
  const verdict = { VERY_SLOW: "don't wait upstream", SLOW: 'plan your own fix', MODERATE: 'monitor upstream', FAST: 'wait for patch' };
  const weatherRows = scan.map(pkg => {
    const speed = speedFor(pkg.days_exposed);
    return `<div class="ti-weather-row">${weatherIcons[speed]}<div class="ti-weather-main"><div class="ti-weather-pkg">${escape(pkg.package)}</div><div class="ti-weather-speed" style="color:${speedColor[speed]}">${speed.replace('_', ' ')}</div></div><div class="ti-weather-verdict">${verdict[speed]}</div></div>`;
  }).join('');
  const safeRows = scan.filter(p => p.actionability === 'SAFE').map(p => `<div class="ti-log-entry ti-log-safe"><span class="ti-log-badge ti-badge-safe">SAFE</span><span class="ti-log-pkg" title="${escape(p.package)}">${escape(p.package)}</span><span class="ti-log-arrow">?</span><span class="ti-log-fix">${escape(p.fix_version)}</span><span class="ti-log-days">${p.days_exposed}d</span></div>`).join('');
  const breakingRows = scan.filter(p => p.actionability === 'BREAKING').sort((a, b) => b.days_exposed - a.days_exposed).map(p => `<div class="ti-log-entry ti-log-breaking"><span class="ti-log-badge ti-badge-breaking">?</span><span class="ti-log-pkg" title="${escape(p.package)}">${escape(p.package)}</span><span class="ti-log-arrow">?</span><span class="ti-log-fix">${escape(p.fix_version)}</span><span class="ti-log-days ti-days-red">${p.days_exposed}d</span></div>`).join('');

  root.innerHTML = `<div class="ti-panels">
    <section class="ti-panel"><div class="ti-panel-header"><svg viewBox="0 0 24 16" width="24" height="16" xmlns="http://www.w3.org/2000/svg"><rect x="0" y="6" width="14" height="5" rx="2" fill="none" stroke="var(--gold)" stroke-width="1.2"/><rect x="13" y="4" width="7" height="9" rx="1.5" fill="none" stroke="var(--gold)" stroke-width="1.2"/><line x1="20" y1="7" x2="24" y2="5" stroke="var(--gold)" stroke-width="1.2"/><line x1="20" y1="11" x2="24" y2="13" stroke="var(--gold)" stroke-width="1.2"/><line x1="6" y1="11" x2="5" y2="16" stroke="var(--gold)" stroke-width="1.2"/><line x1="10" y1="11" x2="10" y2="16" stroke="var(--gold)" stroke-width="1.2"/></svg><span class="ti-panel-label">CHARTED HAZARDS</span></div><div class="ti-panel-body ti-hazards-body"><div class="ti-flag-scroll">${flagsSVG}</div><svg class="ti-seafloor" viewBox="0 0 400 20" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg"><path d="M0,10 C40,5 80,15 120,10 C160,5 200,15 240,10 C280,5 320,15 360,10 C380,7 390,12 400,10" fill="none" stroke="rgba(0,150,200,0.2)" stroke-width="1.5"/><path d="M0,15 C50,10 100,18 150,13 C200,8 250,18 300,13 C350,8 380,16 400,14" fill="none" stroke="rgba(0,150,200,0.1)" stroke-width="1"/></svg><div class="ti-legend"><span class="ti-legend-item" style="color:#FF4444"><span class="ti-pennant"></span>BREAKING</span><span class="ti-legend-item" style="color:#00FF88"><span class="ti-pennant"></span>SAFE</span><span class="ti-legend-item" style="color:#FF8C00"><span class="ti-pennant"></span>MODERATE</span></div></div></section>
    <section class="ti-panel"><div class="ti-panel-header"><svg viewBox="0 0 20 14" width="20" height="14" xmlns="http://www.w3.org/2000/svg"><path d="M4,10 Q2,10 2,8 Q2,5 5,5 Q5,2 9,2 Q13,2 13,5 Q16,4 17,7 Q19,7 19,9 Q19,11 17,11 L5,11 Q4,11 4,10Z" fill="none" stroke="var(--neon-cyan)" stroke-width="1"/><line x1="8" y1="12" x2="7" y2="14" stroke="var(--gold)" stroke-width="1.2"/><line x1="11" y1="12" x2="10" y2="14" stroke="var(--gold)" stroke-width="1.2"/></svg><span class="ti-panel-label">UPSTREAM FORECAST</span></div><div class="ti-panel-body ti-radar-body"><svg class="ti-radar-bg" viewBox="0 0 300 300" xmlns="http://www.w3.org/2000/svg"><defs><radialGradient id="radarFade" cx="50%" cy="50%" r="50%"><stop offset="0%" stop-color="rgba(0,255,200,0.03)"/><stop offset="100%" stop-color="transparent"/></radialGradient></defs><circle cx="150" cy="150" r="140" fill="url(#radarFade)"/><circle cx="150" cy="150" r="100" fill="none" stroke="rgba(0,255,200,0.04)" stroke-width="1"/><circle cx="150" cy="150" r="65" fill="none" stroke="rgba(0,255,200,0.04)" stroke-width="1"/><circle cx="150" cy="150" r="33" fill="none" stroke="rgba(0,255,200,0.04)" stroke-width="1"/><g class="ti-radar-sweep"><line x1="150" y1="150" x2="150" y2="15" stroke="rgba(0,255,136,0.3)" stroke-width="2"/><path d="M150,150 L150,15 A135,135 0 0,1 195,30 Z" fill="rgba(0,255,136,0.06)"/></g></svg><div class="ti-weather-list">${weatherRows}</div></div></section>
    <section class="ti-panel"><div class="ti-panel-header"><svg viewBox="0 0 18 18" width="18" height="18" xmlns="http://www.w3.org/2000/svg"><circle cx="9" cy="9" r="7" fill="none" stroke="var(--gold)" stroke-width="1"/><circle cx="9" cy="9" r="2.5" fill="none" stroke="var(--gold)" stroke-width="1"/><line x1="9" y1="2" x2="9" y2="6.5" stroke="var(--gold)" stroke-width="1"/><line x1="9" y1="11.5" x2="9" y2="16" stroke="var(--gold)" stroke-width="1"/><line x1="2" y1="9" x2="6.5" y2="9" stroke="var(--gold)" stroke-width="1"/><line x1="11.5" y1="9" x2="16" y2="9" stroke="var(--gold)" stroke-width="1"/><line x1="3.9" y1="3.9" x2="6.9" y2="6.9" stroke="var(--gold)" stroke-width="1"/><line x1="11.1" y1="11.1" x2="14.1" y2="14.1" stroke="var(--gold)" stroke-width="1"/><line x1="14.1" y1="3.9" x2="11.1" y2="6.9" stroke="var(--gold)" stroke-width="1"/><line x1="6.9" y1="11.1" x2="3.9" y2="14.1" stroke="var(--gold)" stroke-width="1"/></svg><span class="ti-panel-label">NAVIGATION ORDERS</span></div><div class="ti-panel-body ti-orders-body"><div class="ti-section-header ti-safe"><svg viewBox="0 0 16 20" width="14" height="18" xmlns="http://www.w3.org/2000/svg"><circle cx="8" cy="4" r="3" fill="none" stroke="var(--neon-green)" stroke-width="1.2"/><line x1="8" y1="7" x2="8" y2="18" stroke="var(--neon-green)" stroke-width="1.2"/><path d="M2,11 Q8,14 14,11" fill="none" stroke="var(--neon-green)" stroke-width="1.2"/><path d="M2,18 Q5,15 8,18 Q11,15 14,18" fill="none" stroke="var(--neon-green)" stroke-width="1.2"/></svg><span>SAFE HARBOUR</span><span class="ti-section-sub">do this sprint</span></div>${safeRows || '<div class="ti-log-entry">No safe harbour orders.</div>'}<svg class="ti-rope" viewBox="0 0 200 16" xmlns="http://www.w3.org/2000/svg"><path d="M0,8 C20,4 30,12 50,8 C70,4 80,12 100,8 C120,4 130,12 150,8 C170,4 180,12 200,8" fill="none" stroke="rgba(200,168,75,0.35)" stroke-width="2.5" stroke-linecap="round"/><path d="M0,8 C20,12 30,4 50,8 C70,12 80,4 100,8 C120,12 130,4 150,8 C170,12 180,4 200,8" fill="none" stroke="rgba(200,168,75,0.15)" stroke-width="1"/></svg><div class="ti-section-header ti-breaking"><svg viewBox="0 0 18 20" width="14" height="16" xmlns="http://www.w3.org/2000/svg"><path d="M3,10 Q3,3 9,3 Q15,3 15,10 Q15,14 13,15 L13,17 L5,17 L5,15 Q3,14 3,10Z" fill="none" stroke="var(--neon-red)" stroke-width="1.2"/><circle cx="6.5" cy="10" r="1.8" fill="var(--neon-red)" opacity="0.7"/><circle cx="11.5" cy="10" r="1.8" fill="var(--neon-red)" opacity="0.7"/><line x1="7" y1="17" x2="7" y2="19" stroke="var(--neon-red)" stroke-width="1.5"/><line x1="11" y1="17" x2="11" y2="19" stroke="var(--neon-red)" stroke-width="1.5"/><line x1="5" y1="18" x2="13" y2="18" stroke="var(--neon-red)" stroke-width="1"/></svg><span>STORM AHEAD</span><span class="ti-section-sub">plan migration</span></div>${breakingRows || '<div class="ti-log-entry">No breaking migration orders.</div>'}</div></section>
  </div>`;
}

function showTI2EmptyState() {
  const screen = document.getElementById('screen-patchlag');
  if (!screen) return;
  screen.innerHTML = `
    <div class="ti2-screen">
      <div style="text-align:center;padding:80px 20px;font-family:var(--mono);color:var(--text2);">
        \u2693 No intelligence loaded \u2014 chart a course first.
      </div>
    </div>`;
}

function renderThreatIntel(data) {
  const d = data || window.currentData;
  if (d) window.currentData = d;
  if (!window.currentData?.scan?.length) {
    showTI2EmptyState();
    return;
  }

  const scanSource = window.currentData.scan;
  const ownership = window.currentData.ownership || [];
  const sweep = window.currentData.sweep || {};
  const preCVE = sweep.pre_cve_findings || [];
  const upgradeData = sweep.upgrade_actionability || [];

  const ownerMap = {};
  ownership.forEach(o => {
    if (o.package) ownerMap[o.package.toLowerCase()] = filterBots(o.owners || []);
  });

  const upgradeMap = {};
  upgradeData.forEach(u => {
    const key = (u.package || u.name || '').toLowerCase();
    if (key) upgradeMap[key] = u;
  });

  const preCVENames = new Set(preCVE.map(p => (p.package || p.name || '').toLowerCase()));

  function pkgNameOf(p) { return p.package || p.name || ''; }
  function fixedVersionOf(p, u) {
    return p.fix_version || p.fixed_version || u?.to || u?.fixed_version || u?.fixedVersion || (p.cves && p.cves[0] && p.cves[0].fixed_in) || '?';
  }
  function actionabilityOf(p, u) {
    return p.actionability || u?.kind || u?.actionability || actionabilityForPackage(pkgNameOf(p), sweep) || 'MODERATE';
  }

  const packages = scanSource.map(p => {
    const name = pkgNameOf(p);
    const u = upgradeMap[name.toLowerCase()];
    return {
      package: name,
      version: p.version || u?.from || u?.current_version || '?',
      days_exposed: p.days_exposed || p.worst_days_exposed || 0,
      actionability: actionabilityOf(p, u),
      fix_version: fixedVersionOf(p, u),
      cves: p.cves || [],
      pre_cve: preCVENames.has(name.toLowerCase()),
      owners: ownerMap[name.toLowerCase()] || []
    };
  }).sort((a, b) => (b.days_exposed || 0) - (a.days_exposed || 0));

  if (!packages.length) {
    showTI2EmptyState();
    return;
  }

  renderTI2Deck(packages);
}

function ti2SeededAngle(name) {
  const seed = String(name).split('').reduce((a, c) => ((a << 5) - a + c.charCodeAt(0)) | 0, 0);
  return ((Math.abs(seed) % 161) - 80) / 10;
}

function ti2Weeks(days) { return Math.round((days || 0) / 7); }

function ti2Speed(days) {
  if (days > 500) return 'VERY_SLOW';
  if (days > 150) return 'SLOW';
  if (days > 60) return 'MODERATE';
  return 'FAST';
}

function ti2VerdictReason(speed) {
  return {
    VERY_SLOW: 'maintainers have not shipped a fix despite years of exposure.',
    SLOW: 'maintainer response times exceed safe windows. Plan your own remediation.',
    MODERATE: 'upstream is active but slow. Set a 30-day deadline.',
    FAST: 'upstream patches reliably. Safe to wait for the official release.'
  }[speed];
}

function renderTI2Deck(packages) {
  const screen = document.getElementById('screen-patchlag');
  if (!screen) return;

  const options = packages.map((p, i) =>
    `<option value="${i}">${escape(p.package)}  —  ${ti2Weeks(p.days_exposed)} weeks  ·  ${p.actionability}</option>`
  ).join('');

  function badgeColorFor(act) {
    return act === 'BREAKING' ? '#FF4444' : act === 'SAFE' ? '#00FF88' : '#FFB347';
  }

  const top8 = packages.slice(0, 8);
  // Ensure exactly 8 cards: if fewer real packages exist, repeat the last one
  // so each of the 8 spokes carries a card and none is left empty.
  while (top8.length > 0 && top8.length < 8) {
    top8.push(top8[top8.length - 1]);
  }
  console.log('[helm] top 8 packages on wheel:', top8.map(p => `${p.package}@${p.version} (${p.days_exposed}d)`));
  const WHEEL_CENTER = 300;
  const CARD_RADIUS = 245;
  const CARD_W = 72, CARD_H = 88;

  const rimCards = top8.map((p, i) => {
    const angleRad = (i * 45 - 90) * Math.PI / 180;
    const x = WHEEL_CENTER + CARD_RADIUS * Math.cos(angleRad) - CARD_W / 2;
    const y = WHEEL_CENTER + CARD_RADIUS * Math.sin(angleRad) - CARD_H / 2;
    const tox = (WHEEL_CENTER - x).toFixed(2);
    const toy = (WHEEL_CENTER - y).toFixed(2);
    const color = badgeColorFor(p.actionability);
    const shortName = p.package.length > 10 ? p.package.slice(0, 10) : p.package;
    return `<div class="ti2w-card helm-rim-card" data-idx="${i}">
      <div class="ti2w-card-pkg" title="${escape(p.package)}">${escape(shortName)}</div>
      <div class="ti2w-card-days">${p.days_exposed}</div>
      <div class="ti2w-card-badge" style="color:${color};border-color:${color}">${p.actionability}</div>
    </div>`;
  }).join('');

  const spokeLines = [0,1,2,3,4,5,6,7].map(i => {
    const a = (i * 45 - 90) * Math.PI / 180;
    const x1 = (250 + 32 * Math.cos(a)).toFixed(2);
    const y1 = (250 + 32 * Math.sin(a)).toFixed(2);
    const x2 = (250 + 180 * Math.cos(a)).toFixed(2);
    const y2 = (250 + 180 * Math.sin(a)).toFixed(2);
    return `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="#5C2E0A" stroke-width="10" stroke-linecap="round"/>`;
  }).join('');
  const spokeKnobs = [0,1,2,3,4,5,6,7].map(i => {
    const a = (i * 45 - 90) * Math.PI / 180;
    const cx = (250 + 220 * Math.cos(a)).toFixed(2);
    const cy = (250 + 220 * Math.sin(a)).toFixed(2);
    return `<circle cx="${cx}" cy="${cy}" r="7" fill="#C8A84B"/>`;
  }).join('');

  screen.innerHTML = `
    <style>
      .ti2p-screen { padding: 24px 28px 80px; }
      .ti2p-header { display:flex; align-items:flex-end; justify-content:space-between; flex-wrap:wrap; gap:16px; margin-bottom: 22px; }
      .ti2p-header-text { flex: 1 1 auto; min-width: 0; }
      .ti2p-label { font-family: var(--mono); font-size: 11px; letter-spacing: 3px; color: var(--gold); text-transform: uppercase; margin-bottom: 6px; }
      .ti2p-title { font-size: 26px; font-weight: 700; color: var(--text); margin: 0; }
      .ti2p-subtitle { color: var(--text2); font-size: 13px; margin: 4px 0 0; white-space: normal; overflow: visible; }
      .ti2p-select-wrap { display:flex; flex-direction:column; gap:6px; align-items:flex-end; flex: 0 0 auto; min-width: 280px; }
      .ti2p-select-label { font-family: var(--mono); font-size: 10px; color: var(--gold); letter-spacing: 2px; }
      .ti2p-select { background: linear-gradient(180deg, #071828, #0a2035); border: 1px solid var(--gold); color: var(--gold); font-family: var(--mono); font-size: 12px; padding: 9px 14px; border-radius: 4px; min-width: 320px; cursor:pointer; outline:none; }
      .ti2p-select:focus { box-shadow: 0 0 0 2px rgba(200,168,75,0.2); }
      .ti2p-select option { background: #0a2035; color: var(--text); }

      .ti2w-stage { width: 100%; display: flex; justify-content: center; padding: 30px 0 40px; }
      .ti2w-wheel-container { position: relative; width: 600px; height: 600px; }
      .ti2w-wheel-svg {
        position: absolute; top: 0; left: 0; width: 600px; height: 600px;
        transform-origin: 300px 300px;
        pointer-events: none;
      }
      .ti2w-card.helm-rim-card {
        position: absolute;
        width: 72px; height: 88px;
        background: #0c2340;
        border: 1px solid #C8A84B;
        border-radius: 6px;
        font-size: 10px;
        text-align: center;
        color: var(--text);
        display: flex; flex-direction: column;
        align-items: center; justify-content: center;
        gap: 4px; padding: 6px 4px;
        box-shadow: 0 0 14px rgba(200,168,75,0.35), inset 0 0 6px rgba(200,168,75,0.12);
        cursor: pointer;
        transition: opacity 0.3s, box-shadow 0.3s, border-color 0.3s;
        z-index: 2;
      }
      .ti2w-card.helm-rim-card:hover {
        box-shadow: 0 0 22px rgba(200,168,75,0.6), inset 0 0 8px rgba(200,168,75,0.2);
      }
      .ti2w-card.helm-rim-card.card-active { opacity: 0; }
      .ti2w-card-pkg { font-family: var(--mono); font-size: 9px; font-weight: 700; color: #C8A84B; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 64px; letter-spacing: 0.5px; }
      .ti2w-card-days { font-family: var(--mono); font-size: 20px; font-weight: 700; color: var(--text); line-height: 1; }
      .ti2w-card-badge { font-family: var(--mono); font-size: 8px; letter-spacing: 1px; padding: 2px 4px; border: 1px solid; border-radius: 2px; background: rgba(0,0,0,0.25); }

      #helm-center-card {
        position: absolute;
        left: 210px; top: 200px;
        width: 180px; height: 200px;
        background: #0e2848;
        border: 2px solid #C8A84B;
        border-radius: 8px;
        box-shadow: 0 0 32px rgba(200,168,75,0.55), inset 0 0 12px rgba(200,168,75,0.15);
        z-index: 10;
        display: none;
        flex-direction: column;
        align-items: center; justify-content: center;
        gap: 6px; padding: 14px 12px;
        cursor: pointer;
        color: var(--text); text-align: center;
      }
      #helm-center-card.visible { display: flex; }
      #helm-center-card .cc-pkg { font-family: var(--mono); font-size: 12px; font-weight: 700; color: #C8A84B; word-break: break-word; white-space: normal; width: 100%; text-align: center; }
      #helm-center-card .cc-days { font-family: var(--mono); font-size: 36px; font-weight: 700; color: var(--text); line-height: 1; }
      #helm-center-card .cc-days-lbl { font-family: var(--mono); font-size: 9px; letter-spacing: 1.5px; color: var(--text3); text-transform: uppercase; }
      #helm-center-card .cc-fix { font-family: var(--mono); font-size: 11px; color: var(--neon-cyan); }
      #helm-center-card .cc-badge { font-family: var(--mono); font-size: 10px; letter-spacing: 1.5px; padding: 4px 10px; border: 1px solid; border-radius: 3px; background: rgba(0,0,0,0.3); }
      #helm-center-card .cc-cves { font-family: var(--mono); font-size: 10px; color: var(--text2); }
      #helm-center-card .cc-hint { font-family: var(--mono); font-size: 9px; color: var(--text2); margin-top: 4px; letter-spacing: 0.5px; }

      .ti2w-hint { text-align:center; font-family: var(--mono); font-size: 10px; color: var(--text3); letter-spacing: 2px; margin-top: 16px; text-transform: uppercase; }

      /* ----- Parchment treasure-map modal ----- */
      .ti2p-modal-backdrop { position: fixed; inset: 0; background: rgba(6,12,20,0.78); backdrop-filter: blur(3px); z-index: 999; animation: ti2p-fade-in 0.3s ease; }
      @keyframes ti2p-fade-in { from { opacity: 0; } to { opacity: 1; } }
      .ti2p-parchment {
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        z-index: 1000;
        width: min(880px, 100%); max-height: min(92vh, 800px); overflow: hidden;
        background:
          radial-gradient(ellipse at 20% 15%, rgba(255,230,180,0.45) 0%, transparent 60%),
          radial-gradient(ellipse at 85% 80%, rgba(120,80,40,0.4) 0%, transparent 55%),
          radial-gradient(ellipse at 50% 100%, rgba(80,50,20,0.35) 0%, transparent 50%),
          linear-gradient(150deg, #E8C28F 0%, #D4A96A 30%, #C49A5A 65%, #B8894E 100%);
        color: #3D2B1F;
        font-family: 'Georgia', 'Times New Roman', serif;
        padding: 20px 28px;
        box-shadow: 0 20px 60px rgba(0,0,0,0.7), 0 0 0 1px rgba(60,40,20,0.25);
        clip-path: polygon(
          0% 3%, 3% 0%, 8% 2%, 15% 1%, 22% 3%, 30% 0%, 38% 2%, 46% 0%, 54% 3%, 62% 1%, 70% 2%, 78% 0%, 86% 2%, 94% 1%, 100% 3%,
          99% 12%, 100% 22%, 98% 32%, 100% 44%, 99% 55%, 100% 66%, 98% 78%, 100% 88%, 97% 97%,
          92% 100%, 84% 98%, 76% 100%, 68% 97%, 60% 100%, 52% 98%, 44% 100%, 36% 98%, 28% 100%, 20% 97%, 12% 100%, 4% 98%, 0% 96%,
          2% 86%, 0% 76%, 3% 66%, 0% 56%, 2% 46%, 0% 36%, 3% 24%, 0% 14%
        );
        animation: ti2p-pop-in 0.32s cubic-bezier(0.34, 1.4, 0.64, 1);
      }
      @keyframes ti2p-pop-in { from { opacity: 0; transform: translate(-50%, -50%) scale(0.85); } to { opacity: 1; transform: translate(-50%, -50%) scale(1); } }
      .ti2p-parchment::before {
        content: ''; position: absolute; inset: 0; pointer-events: none;
        background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='240' height='240'><filter id='n'><feTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='2' seed='4'/><feColorMatrix values='0 0 0 0 0.24 0 0 0 0 0.17 0 0 0 0 0.12 0 0 0 0.18 0'/></filter><rect width='240' height='240' filter='url(%23n)'/></svg>");
        opacity: 0.5; mix-blend-mode: multiply;
      }
      .ti2p-parchment > * { position: relative; z-index: 1; }

      .ti2p-compass { position: absolute; top: 28px; left: 32px; width: 90px; height: 90px; opacity: 0.85; }
      .ti2p-ship { position: absolute; top: 34px; right: 64px; width: 120px; height: 76px; opacity: 0.78; }
      .ti2p-pirate { position: absolute; bottom: 30px; right: 42px; width: 72px; height: 112px; opacity: 0.85; }
      .ti2p-seal-close { position: absolute; top: 16px; right: 16px; width: 44px; height: 44px; cursor: pointer; border:none; background:transparent; padding:0; z-index: 10; transition: transform 0.2s; }
      .ti2p-seal-close:hover { transform: rotate(-8deg) scale(1.08); }

      .ti2p-map-head { text-align: center; margin: 0 0 10px; padding-top: 28px; }
      .ti2p-map-pkg { font-family: 'Georgia', serif; font-size: 36px; font-weight: 700; color: #3D2B1F; letter-spacing: 1px; text-shadow: 1px 1px 0 rgba(255,240,210,0.4); margin: 0; word-break: break-word; }
      .ti2p-map-version { font-family: 'Georgia', serif; font-size: 16px; color: #5A3F2A; margin-top: 6px; font-style: italic; }

      .ti2p-speed-box {
        display: inline-block;
        margin: 16px auto 8px;
        padding: 8px 22px;
        font-family: 'Georgia', serif;
        font-size: 16px;
        font-weight: 700;
        letter-spacing: 3px;
        color: #3D2B1F;
        border: 2.5px solid #3D2B1F;
        position: relative;
        transform: rotate(-1.4deg);
        background: rgba(255,240,210,0.2);
      }
      .ti2p-speed-VERY_SLOW { color: #6B1F0F; border-color: #6B1F0F; background: rgba(139,30,15,0.08); }
      .ti2p-speed-SLOW { color: #8B4513; border-color: #8B4513; }
      .ti2p-speed-FAST { color: #2A5028; border-color: #2A5028; background: rgba(42,80,40,0.08); }

      .ti2p-signals { margin: 10px 0 8px; padding: 22px 26px; border: 1.5px dashed rgba(61,43,31,0.55); background: rgba(232,194,143,0.25); }
      .ti2p-signals-title { font-family: 'Georgia', serif; font-size: 14px; letter-spacing: 4px; text-transform: uppercase; color: #3D2B1F; margin: 0 0 16px; border-bottom: 1px solid rgba(61,43,31,0.4); padding-bottom: 6px; }
      .ti2p-signal-row { display: grid; grid-template-columns: 220px 1fr 60px; gap: 14px; align-items: center; padding: 6px 0; }
      .ti2p-signal-label { font-family: 'Georgia', serif; font-size: 13px; color: #3D2B1F; }
      .ti2p-signal-bar-wrap { width: 100%; height: 18px; background: rgba(61,43,31,0.08); border: 1px solid rgba(61,43,31,0.4); position: relative; }
      .ti2p-signal-bar { height: 100%; background: repeating-linear-gradient(45deg, #5A3F2A 0 4px, #6B4A2F 4px 8px); border-right: 1px solid #3D2B1F; }
      .ti2p-signal-score { font-family: 'Georgia', serif; font-size: 14px; font-weight: 700; text-align: right; color: #3D2B1F; }

      .ti2p-jump { margin: 10px 0 10px; text-align: center; font-family: 'Georgia', serif; font-size: 18px; color: #3D2B1F; }
      .ti2p-jump-from { color: #6B1F0F; font-weight: 700; }
      .ti2p-jump-to { color: #2A5028; font-weight: 700; }
      .ti2p-jump-arrow { display: inline-block; margin: 0 14px; font-size: 20px; letter-spacing: 4px; }

      .ti2p-verdict { display: block; visibility: visible; opacity: 1; overflow: visible; white-space: normal; margin: 10px 0 10px; text-align: center; font-family: 'Georgia', serif; font-size: 13px; font-style: italic; color: #3D2B1F; line-height: 1.55; padding: 0 16px; }
      .ti2p-verdict-lead { font-weight: 700; font-style: normal; }

      .ti2p-precve-stamp {
        margin: 10px auto 0; display: flex; align-items: center; gap: 10px;
        font-family: 'Georgia', serif; font-size: 13px; font-weight: 700; letter-spacing: 2px;
        color: #8B0000; border: 3px solid #8B0000;
        padding: 10px 18px; transform: rotate(-6deg);
        width: max-content; max-width: 80%;
        background: rgba(139,0,0,0.06);
        text-transform: uppercase;
      }

      @media (max-width: 780px) {
        .ti2p-parchment { padding: 70px 28px 36px; }
        .ti2p-compass, .ti2p-ship, .ti2p-pirate { display: none; }
        .ti2p-signal-row { grid-template-columns: 120px 1fr 50px; gap: 8px; }
        .ti2p-map-pkg { font-size: 26px; }
      }
    </style>

    <div class="ti2p-screen">
      <div class="ti2p-header">
        <div class="ti2p-header-text">
          <div class="ti2p-label">THREAT INTELLIGENCE</div>
          <h1 class="ti2p-title">The Helm</h1>
          <p class="ti2p-subtitle">Top 8 charted hazards mounted on the helm &middot; select a card to bring it to centre</p>
        </div>
        <div class="ti2p-select-wrap">
          <label class="ti2p-select-label" for="ti2p-select">CHART A HAZARD</label>
          <select class="ti2p-select" id="ti2p-select">${options}</select>
        </div>
      </div>

      <div class="ti2w-stage">
        <div class="ti2w-wheel-container" id="ti2w-wheel">
          <svg class="ti2w-wheel-svg" id="helm-svg" viewBox="0 0 500 500" xmlns="http://www.w3.org/2000/svg">
            <circle cx="250" cy="250" r="220" fill="none" stroke="#3D1F0A" stroke-width="18"/>
            <circle cx="250" cy="250" r="228" fill="none" stroke="#C8A84B" stroke-width="2"/>
            ${spokeLines}
            ${spokeKnobs}
            <circle cx="250" cy="250" r="32" fill="#C8A84B"/>
            <circle cx="250" cy="250" r="18" fill="#3D1F0A"/>
          </svg>
          ${rimCards}
          <div id="helm-center-card"></div>
        </div>
      </div>

      <div class="ti2w-hint">&#9758; click a card on the wheel to open its parchment map</div>
    </div>
  `;

  const select = document.getElementById('ti2p-select');
  const cardEls = Array.from(document.querySelectorAll('#ti2w-wheel .helm-rim-card'));
  const centerCard = document.getElementById('helm-center-card');
  let currentCenterIdx = -1;

  // JS-driven helm: rotate the SVG and position cards at their spoke tips, kept upright.
  let wheelAngle = 0;
  const wheelEl = document.getElementById('helm-svg');
  const rimCardNodes = document.querySelectorAll('.helm-rim-card');
  const centerX = 300;
  const centerY = 300;
  const radius = 255;

  function animateHelm() {
    wheelAngle += 0.06;
    if (wheelEl) wheelEl.style.transform = `rotate(${wheelAngle}deg)`;
    rimCardNodes.forEach((card, i) => {
      const baseAngle = (i * 45) * Math.PI / 180;
      const currentAngle = baseAngle + (wheelAngle * Math.PI / 180);
      const x = centerX + radius * Math.sin(currentAngle) - 36;
      const y = centerY - radius * Math.cos(currentAngle) - 44;
      card.style.left = x + 'px';
      card.style.top = y + 'px';
      card.style.transform = 'none';
    });
    requestAnimationFrame(animateHelm);
  }
  animateHelm();

  function hideCenter() {
    if (!centerCard) return;
    centerCard.classList.remove('visible');
    centerCard.innerHTML = '';
    currentCenterIdx = -1;
    cardEls.forEach(el => el.classList.remove('card-active'));
  }

  function showCenter(idx) {
    const pkg = packages[idx];
    if (!pkg || !centerCard) return;
    currentCenterIdx = idx;
    cardEls.forEach(el => el.classList.remove('card-active'));
    if (idx < cardEls.length) cardEls[idx].classList.add('card-active');
    const color = badgeColorFor(pkg.actionability);
    const cveCount = (pkg.cves || []).length;
    centerCard.innerHTML = `
      <div class="cc-pkg" title="${escape(pkg.package)}">${escape(pkg.package)}</div>
      <div class="cc-days">${pkg.days_exposed}</div>
      <div class="cc-days-lbl">days exposed</div>
      <div class="cc-fix">&rarr; ${escape(pkg.fix_version)}</div>
      <div class="cc-badge" style="color:${color};border-color:${color}">${pkg.actionability}</div>
      <div class="cc-cves">${cveCount} CVE${cveCount === 1 ? '' : 's'}</div>
      <div class="cc-hint">click to open map</div>
    `;
    centerCard.classList.add('visible');
  }

  cardEls.forEach((el, i) => {
    el.style.cursor = 'pointer';
    el.addEventListener('click', (e) => {
      e.stopPropagation();
      if (select) select.value = String(i);
      showCenter(i);
      const pkg = top8[i];
      if (pkg) openTI2ParchmentMap(pkg);
    });
  });

  if (select) {
    select.addEventListener('change', () => {
      const i = Number(select.value);
      if (Number.isFinite(i)) showCenter(i);
    });
  }

  if (centerCard) {
    centerCard.addEventListener('click', (e) => {
      e.stopPropagation();
      if (currentCenterIdx >= 0) openTI2ParchmentMap(packages[currentCenterIdx]);
    });
  }
}

function openTI2ParchmentMap(pkg) {
  const existing = document.getElementById('ti2p-modal');
  if (existing) existing.remove();

  const days = pkg.days_exposed || 0;
  const weeks = ti2Weeks(days);
  const speed = ti2Speed(days);
  const speedLabel = speed.replace('_', ' ');

  const respScore    = days > 500 ? 25 : days > 200 ? 55 : 85;
  const patchScore   = days > 500 ? 20 : days > 200 ? 45 : days > 30 ? 70 : 90;
  const abandonScore = days > 365 ? 30 : days > 90  ? 60 : 85;
  const issueScore   = days > 500 ? 35 : days > 200 ? 60 : 85;
  const prScore      = days > 500 ? 40 : days > 200 ? 65 : 88;

  const signals = [
    { label: 'Maintainer responsiveness', score: respScore },
    { label: 'Patch lag severity',        score: patchScore },
    { label: 'Abandonment signal',        score: abandonScore },
    { label: 'Issue stagnation',          score: issueScore },
    { label: 'PR stagnation',             score: prScore }
  ];

  const signalRows = signals.map(s => `
    <div class="ti2p-signal-row">
      <div class="ti2p-signal-label">${s.label}</div>
      <div class="ti2p-signal-bar-wrap"><div class="ti2p-signal-bar" style="width:${s.score}%"></div></div>
      <div class="ti2p-signal-score">${s.score}/100</div>
    </div>
  `).join('');

  const compassSVG = `<svg class="ti2p-compass" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
    <circle cx="50" cy="50" r="44" fill="none" stroke="#3D2B1F" stroke-width="1.4"/>
    <circle cx="50" cy="50" r="36" fill="none" stroke="#3D2B1F" stroke-width="0.8" stroke-dasharray="2,3"/>
    <g stroke="#3D2B1F" stroke-width="1" fill="rgba(255,220,170,0.4)">
      <polygon points="50,8 54,46 50,50 46,46"/>
      <polygon points="50,92 54,54 50,50 46,54"/>
      <polygon points="8,50 46,46 50,50 46,54"/>
      <polygon points="92,50 54,46 50,50 54,54"/>
      <polygon points="22,22 47,47 50,50 47,53" opacity="0.6"/>
      <polygon points="78,78 53,53 50,50 53,47" opacity="0.6"/>
      <polygon points="22,78 47,53 50,50 53,53" opacity="0.6"/>
      <polygon points="78,22 53,47 50,50 47,47" opacity="0.6"/>
    </g>
    <circle cx="50" cy="50" r="3" fill="#3D2B1F"/>
    <text x="50" y="20" font-family="Georgia,serif" font-size="9" fill="#3D2B1F" text-anchor="middle" font-weight="700">N</text>
    <text x="82" y="53" font-family="Georgia,serif" font-size="9" fill="#3D2B1F" text-anchor="middle">E</text>
    <text x="50" y="86" font-family="Georgia,serif" font-size="9" fill="#3D2B1F" text-anchor="middle">S</text>
    <text x="18" y="53" font-family="Georgia,serif" font-size="9" fill="#3D2B1F" text-anchor="middle">W</text>
  </svg>`;

  const shipSVG = `<svg class="ti2p-ship" viewBox="0 0 120 80" xmlns="http://www.w3.org/2000/svg" fill="none" stroke="#3D2B1F" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round">
    <path d="M14,56 L106,56 L96,68 L24,68 Z" fill="rgba(120,80,40,0.3)"/>
    <line x1="30" y1="56" x2="30" y2="10"/>
    <line x1="60" y1="56" x2="60" y2="6"/>
    <line x1="90" y1="56" x2="90" y2="12"/>
    <path d="M32,12 L52,12 L46,32 L32,32 Z" fill="rgba(255,240,210,0.55)"/>
    <path d="M32,34 L48,34 L42,52 L32,52 Z" fill="rgba(255,240,210,0.55)"/>
    <path d="M62,8 L82,8 L74,30 L62,30 Z" fill="rgba(255,240,210,0.55)"/>
    <path d="M62,32 L78,32 L70,52 L62,52 Z" fill="rgba(255,240,210,0.55)"/>
    <path d="M92,14 L106,14 L100,32 L92,32 Z" fill="rgba(255,240,210,0.55)"/>
    <path d="M5,72 Q15,76 25,72 Q35,76 45,72 Q55,76 65,72 Q75,76 85,72 Q95,76 105,72 Q115,76 120,72" opacity="0.55"/>
  </svg>`;

  const pirateSVG = `<svg class="ti2p-pirate" viewBox="0 0 70 112" xmlns="http://www.w3.org/2000/svg" fill="none" stroke="#3D2B1F" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round">
    <path d="M14,22 Q14,12 35,12 Q56,12 56,22 L60,22 L52,28 L18,28 L10,22 Z" fill="rgba(60,40,20,0.7)" stroke="#3D2B1F"/>
    <path d="M24,18 L28,14 L32,18 L28,22 Z" fill="rgba(255,240,210,0.75)"/>
    <line x1="22" y1="16" x2="34" y2="20"/>
    <circle cx="35" cy="38" r="9" fill="rgba(255,230,200,0.55)"/>
    <line x1="29" y1="36" x2="33" y2="36" stroke-width="2"/>
    <line x1="38" y1="38" x2="42" y2="42"/>
    <line x1="42" y1="38" x2="38" y2="42"/>
    <path d="M30,46 Q35,49 40,46"/>
    <path d="M22,48 L48,48 L52,80 L18,80 Z" fill="rgba(120,80,40,0.4)"/>
    <line x1="22" y1="48" x2="14" y2="68"/>
    <line x1="48" y1="48" x2="58" y2="62"/>
    <line x1="58" y1="62" x2="63" y2="58"/>
    <line x1="14" y1="68" x2="10" y2="74"/>
    <line x1="26" y1="80" x2="22" y2="106"/>
    <line x1="44" y1="80" x2="48" y2="106"/>
    <line x1="18" y1="108" x2="26" y2="108"/>
    <line x1="44" y1="108" x2="52" y2="108"/>
  </svg>`;

  const skullStampSVG = `<svg viewBox="0 0 30 32" width="22" height="24" xmlns="http://www.w3.org/2000/svg" fill="none" stroke="#8B0000" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0">
    <path d="M5,14 Q5,3 15,3 Q25,3 25,14 Q25,20 22,22 L22,26 L8,26 L8,22 Q5,20 5,14Z"/>
    <circle cx="11" cy="14" r="2.5" fill="#8B0000"/>
    <circle cx="19" cy="14" r="2.5" fill="#8B0000"/>
    <line x1="3" y1="30" x2="27" y2="22"/>
    <line x1="3" y1="22" x2="27" y2="30"/>
  </svg>`;

  const closeSealSVG = `<svg viewBox="0 0 44 44" width="44" height="44" xmlns="http://www.w3.org/2000/svg">
    <circle cx="22" cy="22" r="19" fill="#8B0000" stroke="#5A0000" stroke-width="1.5"/>
    <circle cx="22" cy="22" r="15" fill="none" stroke="#FFE5C2" stroke-width="0.8" stroke-dasharray="2,2"/>
    <line x1="15" y1="15" x2="29" y2="29" stroke="#FFE5C2" stroke-width="2.5" stroke-linecap="round"/>
    <line x1="29" y1="15" x2="15" y2="29" stroke="#FFE5C2" stroke-width="2.5" stroke-linecap="round"/>
  </svg>`;

  const modal = document.createElement('div');
  modal.id = 'ti2p-modal';
  modal.className = 'ti2p-modal-backdrop';
  modal.innerHTML = `
    <div class="ti2p-parchment" role="dialog" aria-label="Hazard map for ${escape(pkg.package)}">
      <button class="ti2p-seal-close" id="ti2p-close" aria-label="Close">${closeSealSVG}</button>
      ${compassSVG}
      ${shipSVG}

      <div class="ti2p-map-head">
        <h2 class="ti2p-map-pkg">${escape(pkg.package)}</h2>
        <div class="ti2p-map-version">version ${escape(pkg.version)} &middot; ${weeks} weeks exposed</div>
        <div class="ti2p-speed-box ti2p-speed-${speed}">${speedLabel}</div>
      </div>

      <div class="ti2p-signals">
        <div class="ti2p-signals-title">&#9875; Upstream Health Signals</div>
        ${signalRows}
      </div>

      <div class="ti2p-jump">
        <span class="ti2p-jump-from">v${escape(pkg.version)}</span>
        <span class="ti2p-jump-arrow">- - &#9658;</span>
        <span class="ti2p-jump-to">v${escape(pkg.fix_version)}</span>
      </div>

      <div class="ti2p-verdict">
        <span class="ti2p-verdict-lead">Upstream will not save you</span> &mdash; ${ti2VerdictReason(speed)}
      </div>

      ${pkg.pre_cve ? `
        <div class="ti2p-precve-stamp">
          ${skullStampSVG}<span>PRE-CVE SIGNAL &mdash; NO SCANNER ALERT YET</span>
        </div>
      ` : ''}
    </div>
  `;

  modal.addEventListener('click', e => {
    if (e.target === modal) modal.remove();
  });
  document.body.appendChild(modal);

  const closeBtn = document.getElementById('ti2p-close');
  if (closeBtn) closeBtn.addEventListener('click', () => modal.remove());

  const escListener = (e) => {
    if (e.key === 'Escape') {
      modal.remove();
      document.removeEventListener('keydown', escListener);
    }
  };
  document.addEventListener('keydown', escListener);
}

function renderPatchLag(d) {
  renderThreatIntel(d);
  return;
  const scan = d.scan || [];
  const ownership = d.ownership || [];
  const sweep = d.sweep || {};

  // Join scan × ownership by package name (case-insensitive)
  const ownerMap = {};
  ownership.forEach(o => {
    if (o && o.package) ownerMap[String(o.package).toLowerCase()] = o;
  });
  const joinedData = scan.map(p => {
    const own = ownerMap[String(p.name || '').toLowerCase()];
    const days = p.worst_days_exposed || 0;
    const cves = p.cves || [];
    const fix_version = own?.fixed_in
      || (cves[0] && cves[0].fixed_in)
      || '?';
    const actionability = own?.actionability
      || actionabilityForPackage(p.name, sweep)
      || 'BREAKING';
    const owners = own ? filterBots(own.owners) : [];
    const ticket_text = own?.ticket_text
      || `@${owners[0] || 'team'} — ${p.name} exposed ${days}d, ${actionability} fix → upgrade to ${fix_version}`;
    return {
      package: p.name,
      version: p.version,
      days_exposed: days,
      fix_version,
      actionability,
      cves,
      owners,
      ticket_text,
    };
  });

  // ACT 1 — Hero
  const totalCveDays = joinedData.reduce((s, r) => s + r.days_exposed * r.cves.length, 0);
  const safeCount = joinedData.filter(r => r.actionability === 'SAFE').length;
  const hero = document.getElementById('plHero');
  if (hero) {
    hero.innerHTML = `
      <div class="pl-hero-numwrap">
        <span class="pl-hero-number gold-metal">${totalCveDays.toLocaleString()}</span>
        <span class="pl-hero-unit">CVE-days of negligence</span>
      </div>
      <div class="pl-hero-sub">
        <span class="pl-hero-safe">${safeCount}</span> packages had a SAFE fix available and were never upgraded.<br>
        Your team <span class="pl-hero-condemn">chose not to act</span>. Here is the evidence.
      </div>
    `;
  }

  // ACT 2 — Sort by urgency, render rows
  joinedData.forEach(r => {
    r._urgency = (r.days_exposed / 2090) * 60
               + (r.cves.length / 7) * 25
               + (r.actionability === 'BREAKING' ? 10 : 0);
  });
  joinedData.sort((a, b) => b._urgency - a._urgency);

  const maxDays = Math.max(1, ...joinedData.map(r => r.days_exposed));

  function quadrant(r) {
    if (r.actionability === 'SAFE' && r.days_exposed > 100) return { cls: 'no-excuse', text: 'NO EXCUSE' };
    if (r.actionability === 'BREAKING' && r.days_exposed > 200) return { cls: 'hard', text: 'HARD PROBLEM' };
    if (r.actionability === 'SAFE' && r.days_exposed <= 100) return { cls: 'act-now', text: 'ACT NOW' };
    return { cls: 'watching', text: 'WATCHING' };
  }

  const container = document.getElementById('plTimeline');
  if (!container) return;
  container.innerHTML = '';

  joinedData.forEach(r => {
    const row = document.createElement('div');
    row.className = 'pl-row';

    const main = document.createElement('div');
    main.className = 'pl-row-main';

    // LEFT — package, version, owners
    const left = document.createElement('div');
    left.className = 'pl-left';
    const pkgName = document.createElement('div');
    pkgName.className = 'pl-pkg-name';
    pkgName.textContent = r.package;
    const ver = document.createElement('div');
    ver.className = 'pl-pkg-version';
    ver.textContent = r.version || '?';
    left.appendChild(pkgName);
    left.appendChild(ver);
    if (r.owners.length === 0) {
      const none = document.createElement('div');
      none.className = 'pl-no-owner';
      none.textContent = '? unowned';
      left.appendChild(none);
    } else {
      const ownersWrap = document.createElement('div');
      ownersWrap.className = 'pl-owners';
      r.owners.slice(0, 2).forEach(o => {
        const b = document.createElement('span');
        b.className = 'pl-owner-badge';
        b.textContent = '@' + (o.length > 8 ? o.substring(0, 8) : o);
        ownersWrap.appendChild(b);
      });
      left.appendChild(ownersWrap);
    }

    // CENTER — timeline track
    const center = document.createElement('div');
    center.className = 'pl-center';

    const trackWrap = document.createElement('div');
    trackWrap.className = 'pl-track-wrap';
    const track = document.createElement('div');
    track.className = 'pl-track';

    // Optional "Before CVE" segment if cves[0].published available
    let beforePct = 0;
    if (r.cves[0] && r.cves[0].published) {
      const pub = new Date(r.cves[0].published);
      if (!isNaN(pub.getTime())) {
        const ageDays = Math.max(0, Math.floor((Date.now() - pub.getTime()) / 86400000));
        if (ageDays > r.days_exposed) {
          const beforeDays = ageDays - r.days_exposed;
          beforePct = Math.min(20, (beforeDays / maxDays) * 100);
        }
      }
    }
    const ignoredPct = Math.max(4, (r.days_exposed / maxDays) * 100);

    if (beforePct > 0) {
      const seg1 = document.createElement('div');
      seg1.className = 'pl-seg-before';
      seg1.style.width = beforePct + '%';
      seg1.title = 'Before CVE';
      track.appendChild(seg1);
    }
    const seg2 = document.createElement('div');
    seg2.className = 'pl-seg-ignored';
    seg2.style.width = ignoredPct + '%';
    seg2.title = 'Fix Available, Ignored';
    track.appendChild(seg2);

    const seg3 = document.createElement('div');
    seg3.className = 'pl-seg-today';
    const todayLabel = document.createElement('span');
    todayLabel.className = 'pl-today-label';
    todayLabel.textContent = 'TODAY';
    seg3.appendChild(todayLabel);
    track.appendChild(seg3);

    trackWrap.appendChild(track);

    const captionRow = document.createElement('div');
    captionRow.className = 'pl-caption-row';
    const caption = document.createElement('div');
    caption.className = 'pl-track-caption';
    caption.style.left = (beforePct + ignoredPct / 2) + '%';
    caption.textContent = `Ignored: ${r.days_exposed}d`;
    captionRow.appendChild(caption);

    center.appendChild(trackWrap);
    center.appendChild(captionRow);

    // RIGHT — quadrant + cve count
    const right = document.createElement('div');
    right.className = 'pl-right';
    const q = quadrant(r);
    const badge = document.createElement('span');
    badge.className = 'pl-badge ' + q.cls;
    badge.textContent = q.text;
    right.appendChild(badge);
    const cveCt = document.createElement('div');
    cveCt.className = 'pl-cve-count';
    cveCt.textContent = r.cves.length + ' CVE' + (r.cves.length === 1 ? '' : 's');
    right.appendChild(cveCt);

    main.appendChild(left);
    main.appendChild(center);
    main.appendChild(right);

    // DETAIL — CVE list + ticket
    const detail = document.createElement('div');
    detail.className = 'pl-detail';
    const inner = document.createElement('div');
    inner.className = 'pl-detail-inner';

    const cveBlock = document.createElement('div');
    cveBlock.className = 'pl-detail-cves';
    const cveLabel = document.createElement('div');
    cveLabel.className = 'pl-block-label';
    cveLabel.textContent = 'CVEs';
    cveBlock.appendChild(cveLabel);
    if (r.cves.length === 0) {
      const none = document.createElement('div');
      none.style.cssText = 'color:var(--text3);font-size:11px;font-family:var(--mono);';
      none.textContent = '? no CVEs in record';
      cveBlock.appendChild(none);
    }
    r.cves.forEach(c => {
      const item = document.createElement('div');
      item.className = 'pl-cve-item';
      const sevRaw = String(c.severity || 'MEDIUM').toLowerCase();
      const sevCls = sevRaw === 'critical' ? 'critical'
                  : sevRaw === 'high'     ? 'high'
                  : sevRaw === 'low'      ? 'low'
                  : 'medium';
      const sevBadge = document.createElement('span');
      sevBadge.className = 'pl-sev-badge ' + sevCls;
      sevBadge.textContent = sevCls.toUpperCase();
      const id = document.createElement('span');
      id.className = 'pl-cve-id';
      id.textContent = c.id || '?';
      const sum = document.createElement('span');
      sum.className = 'pl-cve-sum';
      const sumText = c.summary || '?';
      sum.textContent = '— ' + (sumText.length > 80 ? sumText.substring(0, 80) + '…' : sumText);
      item.appendChild(sevBadge);
      item.appendChild(id);
      item.appendChild(sum);
      cveBlock.appendChild(item);
    });

    const ticketBlock = document.createElement('div');
    ticketBlock.className = 'pl-detail-ticket';
    const tLabel = document.createElement('div');
    tLabel.className = 'pl-block-label';
    tLabel.textContent = 'Assign to crew';
    const tBody = document.createElement('div');
    tBody.className = 'pl-ticket-text';
    tBody.textContent = r.ticket_text;
    const btn = document.createElement('button');
    btn.className = 'pl-copy-btn';
    btn.type = 'button';
    btn.textContent = 'COPY TICKET';
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const reset = () => {
        btn.textContent = 'COPY TICKET';
        btn.classList.remove('copied');
      };
      const onOk = () => {
        btn.textContent = '? COPIED';
        btn.classList.add('copied');
        setTimeout(reset, 2000);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(r.ticket_text).then(onOk).catch(onOk);
      } else {
        onOk();
      }
    });
    ticketBlock.appendChild(tLabel);
    ticketBlock.appendChild(tBody);
    ticketBlock.appendChild(btn);

    inner.appendChild(cveBlock);
    inner.appendChild(ticketBlock);
    detail.appendChild(inner);

    row.appendChild(main);
    row.appendChild(detail);

    main.addEventListener('click', () => {
      const wasOpen = row.classList.contains('open');
      container.querySelectorAll('.pl-row.open').forEach(r => r.classList.remove('open'));
      if (!wasOpen) row.classList.add('open');
    });

    container.appendChild(row);
  });
}

function renderPreCve(d) {
  const sweep = d.sweep || {};
  const findings = (sweep.pre_cve_findings || []).filter(f => f.has_security_deprecation);

  if (findings.length > 0) {
    document.getElementById('stormSection').innerHTML = findings.map(f => {
      const dep = (f.security_deprecations && f.security_deprecations[0]) || {};
      return `
        <div class="storm-card">
          <span class="badge precve">PRE-CVE · NO SCANNER ALERT YET</span>
          <div class="pkg">${escape(f.name)} @ ${escape(f.installed_version || '?')}</div>
          <div class="reason">"${escape(dep.reason || 'Security-related deprecation in upstream registry')}"</div>
          <div class="meta">Deprecated version: ${escape(dep.version || '?')} · ${dep.days_ago || '?'} days ago · ${escape(f.system || '')}</div>
        </div>
      `;
    }).join('') + '<div class="storm-tagline">No CVE filed yet — this is your early warning. Every scanner is silent. DriftWatch fires.</div>';
  } else {
    document.getElementById('stormSection').innerHTML = `
      <div class="empty-state">
        No security deprecations detected in this scan's packages — <span style="color:var(--green)">clean waters ahead</span>.<br>
        <span style="font-size:11px; color:var(--text3); margin-top:8px; display:inline-block">Run a full sweep to detect pre-CVE signals across all dependencies.</span>
      </div>
    `;
  }

  // Signal section: top 5 packages by exposure
  const top5 = (d.scan || []).slice().sort((a, b) => (b.worst_days_exposed || 0) - (a.worst_days_exposed || 0)).slice(0, 5);
  document.getElementById('signalSection').innerHTML = top5.map(p => {
    const days = p.worst_days_exposed || 0;
    const respScore = days > 500 ? 25 : days > 200 ? 55 : 85;
    const patchScore = days > 500 ? 20 : days > 200 ? 45 : days > 30 ? 70 : 90;
    const abandonScore = days > 365 ? 30 : days > 90 ? 60 : 85;
    const issueScore = days > 500 ? 35 : days > 200 ? 60 : 85;
    const prScore = days > 500 ? 40 : days > 200 ? 65 : 88;
    const signals = [
      ['Maintainer responsiveness', respScore],
      ['Patch lag severity', patchScore],
      ['Abandonment signal', abandonScore],
      ['Issue stagnation', issueScore],
      ['PR stagnation', prScore],
    ];
    return `
      <div class="signal-card">
        <div class="pkg">${escape(p.name)} <span style="color:var(--text2);font-weight:400">@ ${escape(p.version)} · ${days}d exposed</span></div>
        ${signals.map(([name, val]) => {
          const cls = val < 40 ? 'red' : val < 70 ? 'amber' : '';
          return `
            <div class="signal-bar">
              <div class="signal-label">${name}</div>
              <div class="signal-track"><div class="signal-fill ${cls}" style="width: ${val}%"></div></div>
              <div class="signal-score">${val}/100</div>
            </div>`;
        }).join('')}
      </div>
    `;
  }).join('');
}

function renderMaintainer(d) {
  const scan = (d.scan || []).slice().sort((a, b) => (b.worst_days_exposed || 0) - (a.worst_days_exposed || 0));
  document.getElementById('maintGrid').innerHTML = scan.map(p => {
    const days = p.worst_days_exposed || 0;
    let label, cls, decision;
    if (days < 60) { label = 'FAST'; cls = 'fast'; decision = 'Upstream patches quickly — safe to wait for the official fix.'; }
    else if (days < 200) { label = 'MODERATE'; cls = 'moderate'; decision = 'Set a 30-day deadline — monitor upstream actively.'; }
    else if (days < 500) { label = 'SLOW'; cls = 'slow'; decision = 'Do not wait — plan mitigation now.'; }
    else { label = 'VERY SLOW'; cls = 'veryslow'; decision = 'Upstream will not save you — mitigate immediately.'; }
    return `
      <div class="maint-card">
        <div class="pkg">${escape(p.name)}</div>
        <div class="ver">@ ${escape(p.version)} · ${(p.cves || []).length} CVE${(p.cves || []).length === 1 ? '' : 's'}</div>
        <div class="maint-resp ${cls}">${label} RESPONSIVENESS</div>
        <div class="maint-decision">${decision}</div>
        <div class="maint-exp">Inferred from ${days} days patch lag</div>
      </div>
    `;
  }).join('');
}

function renderOrders(d) {
  const sweep = d.sweep || {};
  const ua = sweep.upgrade_actionability || [];

  function dedupe(rows) {
    // pick lowest-version fix per package (first occurrence after sort by days desc)
    const seen = new Map();
    rows.forEach(r => {
      if (!seen.has(r.name)) seen.set(r.name, r);
    });
    return Array.from(seen.values()).sort((a, b) => (b.days_exposed || 0) - (a.days_exposed || 0));
  }

  const safe = dedupe(ua.filter(u => u.actionability === 'SAFE'));
  const breaking = dedupe(ua.filter(u => u.actionability === 'BREAKING'));

  function card(row, cls) {
    return `
      <div class="order-card ${cls}">
        <div class="order-head">
          <div class="order-pkg">${escape(row.name)} <span style="color:var(--text2)">${escape(row.current_version)}</span> <span class="order-arrow">?</span> <span style="color:var(--green)">${escape(row.fixed_version)}</span></div>
          <div class="order-days">${row.days_exposed}d exposed</div>
        </div>
        <div class="order-exp">${escape(row.explanation || '')}</div>
      </div>
    `;
  }

  document.getElementById('ordersSafe').innerHTML = safe.length
    ? safe.map(r => card(r, 'safe')).join('')
    : '<div class="empty-state">No safe (patch/minor) upgrades available in current scan.</div>';

  document.getElementById('ordersBreaking').innerHTML = breaking.length
    ? breaking.map(r => card(r, 'breaking')).join('')
    : '<div class="empty-state">No breaking upgrades required.</div>';
}

function buildCrewMap(data) {
  // ownerMap: package name (lowercase) → { owners, ticket_text, actionability, fixed_in }
  const ownerMap = {};
  (data.ownership || []).forEach(o => {
    const key = String(o.package || '').toLowerCase();
    ownerMap[key] = {
      owners: filterBots(o.owners || []),
      ticket_text: o.ticket_text || '',
      actionability: o.actionability || '',
      fixed_in: o.fixed_in || '',
      files: o.files || [],
      manifest_path: o.manifest_path || 'package.json',
      manifest_touches: o.manifest_touches || []
    };
  });

  // Sweep upgrade map: pkg name → most-severe row (by days_exposed)
  const sweep = data.sweep || {};
  const upgradeMap = {};
  (sweep.upgrade_actionability || []).forEach(u => {
    if (!upgradeMap[u.name] || (u.days_exposed || 0) > (upgradeMap[u.name].days_exposed || 0)) {
      upgradeMap[u.name] = u;
    }
  });

  // crewMap: owner login → stats
  const crewMap = {};
  (data.scan || []).forEach(pkg => {
    const pkgName = pkg.name;
    if (!pkgName) return;
    const key = pkgName.toLowerCase();
    const ownerData = ownerMap[key] || { owners: [], ticket_text: '', actionability: '', fixed_in: '' };
    const owners = ownerData.owners;
    const upgrade = upgradeMap[pkgName] || {};
    const actionability = ownerData.actionability || upgrade.actionability || 'BREAKING';
    const fixVersion = ownerData.fixed_in || upgrade.fixed_version || (pkg.cves && pkg.cves[0] && pkg.cves[0].fixed_in) || '?';
    const daysExposed = pkg.worst_days_exposed || 0;

    owners.forEach(login => {
      if (!crewMap[login]) {
        crewMap[login] = {
          login,
          packages: [],
          totalDays: 0,
          safeIgnored: 0,
          breakingCount: 0
        };
      }
      // Only add if not already in this person's list
      const alreadyHas = crewMap[login].packages.some(p => p.name === pkgName);
      if (!alreadyHas) {
      crewMap[login].packages.push({
        name: pkgName,
        version: pkg.version,
        days_exposed: daysExposed,
        actionability,
        fix_version: fixVersion,
        cve_count: (pkg.cves || []).length,
        files: ownerData.files || [],
        manifest_path: ownerData.manifest_path || 'package.json',
        manifest_touches: ownerData.manifest_touches || [],
        ticket_text: ownerData.ticket_text
          || `@${login} — ${pkgName} exposed ${daysExposed}d, ${actionability} fix → upgrade to ${fixVersion}`
      });
        crewMap[login].totalDays += daysExposed;
        if (actionability === 'SAFE') crewMap[login].safeIgnored++;
        if (actionability === 'BREAKING') crewMap[login].breakingCount++;
      }
    });
  });

  return Object.values(crewMap).sort((a, b) => b.totalDays - a.totalDays);
}

// -- SVG helpers (module scope) --
function skullStampSVG(size) {
  size = size || 60;
  return `<svg width="${size}" height="${size}" viewBox="0 0 60 60" xmlns="http://www.w3.org/2000/svg">
    <ellipse cx="30" cy="26" rx="16" ry="15" fill="rgba(255,68,68,0.9)" stroke="#FF4444" stroke-width="1"/>
    <ellipse cx="24" cy="25" rx="4" ry="4.5" fill="#061420"/>
    <ellipse cx="36" cy="25" rx="4" ry="4.5" fill="#061420"/>
    <path d="M28.5 31 L30 29 L31.5 31 Z" fill="#061420"/>
    <rect x="22" y="34" width="4" height="5" rx="1" fill="rgba(255,68,68,0.9)" stroke="#FF4444" stroke-width="0.5"/>
    <rect x="28" y="34" width="4" height="5" rx="1" fill="rgba(255,68,68,0.9)" stroke="#FF4444" stroke-width="0.5"/>
    <rect x="34" y="34" width="4" height="5" rx="1" fill="rgba(255,68,68,0.9)" stroke="#FF4444" stroke-width="0.5"/>
    <line x1="8" y1="48" x2="52" y2="12" stroke="#FF4444" stroke-width="4" stroke-linecap="round" opacity="0.8"/>
    <line x1="52" y1="48" x2="8" y2="12" stroke="#FF4444" stroke-width="4" stroke-linecap="round" opacity="0.8"/>
    <circle cx="8" cy="48" r="4" fill="#FF4444" opacity="0.8"/>
    <circle cx="52" cy="12" r="4" fill="#FF4444" opacity="0.8"/>
    <circle cx="52" cy="48" r="4" fill="#FF4444" opacity="0.8"/>
    <circle cx="8" cy="12" r="4" fill="#FF4444" opacity="0.8"/>
    <circle cx="30" cy="30" r="28" fill="none" stroke="#FF4444" stroke-width="2" stroke-dasharray="4 3" opacity="0.6"/>
  </svg>`;
}

function telescopeSVG() {
  return `<svg width="14" height="14" viewBox="0 0 14 14" xmlns="http://www.w3.org/2000/svg" style="vertical-align:middle">
    <line x1="2" y1="10" x2="12" y2="4" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"/>
    <line x1="10" y1="3" x2="13" y2="5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
    <line x1="1" y1="9" x2="4" y2="11" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
    <circle cx="12" cy="3.5" r="1.5" fill="currentColor" opacity="0.6"/>
  </svg>`;
}

function treasureSVG(size) {
  size = size || 20;
  return `<svg width="${size}" height="${size}" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg" style="vertical-align:middle">
    <rect x="2" y="9" width="16" height="9" rx="1" fill="rgba(200,168,75,0.3)" stroke="#C8A84B" stroke-width="1"/>
    <rect x="2" y="7" width="16" height="4" rx="1" fill="rgba(200,168,75,0.5)" stroke="#C8A84B" stroke-width="1"/>
    <rect x="2" y="9" width="16" height="2" fill="rgba(200,168,75,0.4)"/>
    <rect x="8" y="10" width="4" height="4" rx="1" fill="rgba(200,168,75,0.8)" stroke="#F0D898" stroke-width="0.5"/>
    <line x1="2" y1="13" x2="18" y2="13" stroke="rgba(200,168,75,0.3)" stroke-width="0.5"/>
    <circle cx="4" cy="12" r="1" fill="rgba(200,168,75,0.4)"/>
    <circle cx="16" cy="12" r="1" fill="rgba(200,168,75,0.4)"/>
  </svg>`;
}

function coinSVG() {
  return `<svg width="16" height="16" viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
    <defs>
      <radialGradient id="coinGrad" cx="35%" cy="30%">
        <stop offset="0%" stop-color="#F0D898"/>
        <stop offset="60%" stop-color="#C8A84B"/>
        <stop offset="100%" stop-color="#8B6914"/>
      </radialGradient>
    </defs>
    <circle cx="8" cy="8" r="7" fill="url(#coinGrad)" stroke="#F0D898" stroke-width="0.5"/>
    <text x="8" y="11" text-anchor="middle" font-size="8" font-family="serif" font-weight="bold" fill="#4A3000">$</text>
  </svg>`;
}

function renderCrew(d) {
  var crewList = document.getElementById('crewList');
  if (!crewList) return;
  crewList.innerHTML = '';

  var crew = buildCrewMap(d);

  if (crew.length === 0) {
    crewList.innerHTML = '<div style="padding:40px;text-align:center;font-family:var(--mono);color:var(--text3)">No crew data charted. Load a repository with ownership data.</div>';
    return;
  }

  var captain = crew[0];
  var officers = crew.slice(1, 4);
  var captainWeeks = Math.round(captain.totalDays / 7);

  var layout = document.createElement('div');
  layout.className = 'crew-layout';

  // Captain card (top, centered)
  var captainCard = document.createElement('div');
  captainCard.className = 'captain-card';
  captainCard.onclick = (function(p) { return function() { openCrewBook(p); }; })(captain);
  captainCard.innerHTML =
    '<div class="captain-rank-label">⚓ CAPTAIN</div>' +
    '<div class="captain-username gold-metal">@' + captain.login + '</div>' +
    '<div class="captain-days">' + captain.totalDays.toLocaleString() + '</div>' +
    '<div class="captain-days-label">days of exposure</div>' +
    '<div class="captain-stats-row">' + captain.packages.length + ' PACKAGES · ' + captain.breakingCount + ' BREAKING · ' + captain.safeIgnored + ' EASY WINS</div>' +
    '<div class="captain-subtitle">Responsible for ' + captainWeeks + 'w of exposure</div>';
  layout.appendChild(captainCard);

  // Officers row (below captain)
  if (officers.length > 0) {
    var officersRow = document.createElement('div');
    officersRow.className = 'officers-row';
    officers.forEach(function(member) {
      var card = document.createElement('div');
      card.className = 'officer-card';
      card.onclick = (function(m) { return function() { openCrewBook(m); }; })(member);
      card.innerHTML =
        '<div class="officer-rank-label">🔱 OFFICER</div>' +
        '<div class="officer-username">@' + member.login + '</div>' +
        '<div class="officer-days">' + member.totalDays.toLocaleString() + '</div>' +
        '<div class="officer-days-label">days of exposure</div>' +
        '<div class="officer-stats">' + member.packages.length + ' pkgs · ' + member.breakingCount + ' breaking</div>';
      officersRow.appendChild(card);
    });
    layout.appendChild(officersRow);
  }

  crewList.appendChild(layout);
}

// Book modal state
var _bookPerson = null;
var _bookCurrentSpread = 0;
var _bookSpreads = [];

function _sinceDate(days) {
  var dt = new Date(Date.now() - days * 86400000);
  return dt.toLocaleDateString('en-GB', { month: 'short', year: 'numeric' });
}

function buildSpreads(person) {
  var pkgs = person.packages.slice().sort(function(a, b) {
    return (b.days_exposed || 0) - (a.days_exposed || 0);
  });
  // Each spread = 4 packages (2 per page)
  var spreads = [];
  for (var i = 0; i < pkgs.length; i += 4) {
    spreads.push({
      left: [pkgs[i] || null, pkgs[i+1] || null],
      right: [pkgs[i+2] || null, pkgs[i+3] || null]
    });
  }
  return spreads;
}

function renderPkgEntry(pkg, person) {
  if (!pkg) return '';
  var badge = (pkg.actionability === 'SAFE')
    ? '<span class="book-badge-safe">SAFE</span>'
    : '<span class="book-badge-breaking">BREAKING</span>';
  var fixVer = pkg.fix_version && pkg.fix_version !== '?' ? pkg.fix_version : '(see OSV)';
  var since = _sinceDate(pkg.days_exposed || 0);
  var days = (pkg.days_exposed || 0).toLocaleString();
  var weeks = Math.round((pkg.days_exposed || 0) / 7);
  return '<div class="pkg-entry">' +
    '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">' +
      '<span style="font-size:19px;font-weight:bold;color:#2C1810;font-family:Georgia,serif;">' + pkg.name + '</span>' +
      badge +
    '</div>' +
    '<div style="font-size:44px;font-weight:bold;color:#8B1A1A;font-family:Georgia,serif;line-height:1;">' + days +
      '<span style="font-size:14px;color:#6B3A1F;font-weight:normal;"> days (' + weeks + 'w)</span>' +
    '</div>' +
    '<div style="font-size:12.5px;color:#3D1F0A;margin-top:8px;line-height:2;">' +
      '📅 Since ' + since + '<br>' +
      '🔧 Fix: v' + (pkg.version || '?') + ' → v' + fixVer + '<br>' +
      '👤 Owner: @' + person.login +
    '</div>' +
  '</div>';
}

function renderPageHtml(pkgPair, person, pageNum, totalPages) {
  var pkgs = pkgPair.filter(function(p) { return p !== null; });
  if (pkgs.length === 0) {
    return '<div style="height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;font-family:Georgia,serif;">' +
      '<svg width="60" height="60" viewBox="0 0 60 60" fill="none"><circle cx="30" cy="30" r="28" stroke="#C8A84B" stroke-width="2"/><path d="M30 12 L30 26 M24 32 C24 38 27 44 30 46 C33 44 36 38 36 32 C36 26 30 26 30 26 C30 26 24 26 24 32Z" stroke="#8B6914" stroke-width="2" fill="none"/><circle cx="30" cy="20" r="3" fill="#C8A84B"/><path d="M18 42 L42 42" stroke="#C8A84B" stroke-width="1.5"/></svg>' +
      '<div style="color:#8B6914;font-style:italic;text-align:center;margin-top:12px;">All charges logged.<br/>Fair winds ahead — if you act.</div>' +
    '</div>';
  }
  var header = '<div class="book-page-header"><span>@' + person.login + '</span><span>Page ' + pageNum + ' of ' + totalPages + '</span></div>';
  var inner = '<div class="book-page-body" style="flex:1;display:flex;flex-direction:column;overflow:hidden;">';
  if (pkgs.length === 1) {
    inner += renderPkgEntry(pkgs[0], person);
    inner += '<div style="flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;border-top:1px dashed rgba(139,94,60,0.4);color:#8B6914;font-family:Georgia,serif;font-style:italic;font-size:13px;text-align:center;gap:8px;">' +
      '<svg width="28" height="28" viewBox="0 0 28 28"><text x="14" y="20" text-anchor="middle" font-size="20">⚓</text></svg>' +
      'All charges logged.<br>Fair winds ahead — if you act.' +
    '</div>';
  } else {
    inner += renderPkgEntry(pkgs[0], person) + renderPkgEntry(pkgs[1], person);
  }
  inner += '</div>';
  return header + inner;
}

function updateBookContent(person, spread) {
  var leftPage = document.getElementById('book-left-page');
  var rightPage = document.getElementById('book-right-page');
  if (!leftPage || !rightPage) return;
  if (!_bookSpreads.length) return;

  var s = _bookSpreads[spread];
  var totalPages = _bookSpreads.length * 2;
  leftPage.innerHTML = renderPageHtml(s.left, person, spread * 2 + 1, totalPages);
  rightPage.innerHTML = renderPageHtml(s.right, person, spread * 2 + 2, totalPages);

  var prevBtn = document.getElementById('book-prev');
  var nextBtn = document.getElementById('book-next');
  if (prevBtn) prevBtn.style.display = spread === 0 ? 'none' : '';
  if (nextBtn) nextBtn.style.display = spread === _bookSpreads.length - 1 ? 'none' : '';
}

function openCrewBook(person) {
  _bookPerson = person;
  _bookSpreads = buildSpreads(person);
  _bookCurrentSpread = 0;

  updateBookContent(person, 0);

  var overlay = document.getElementById('crew-book-overlay');
  if (overlay) overlay.classList.add('open');
}

function closeCrewBook() {
  var overlay = document.getElementById('crew-book-overlay');
  if (overlay) overlay.classList.remove('open');
}

function bookNext() {
  if (_bookCurrentSpread >= _bookSpreads.length - 1) return;
  _bookCurrentSpread++;
  updateBookContent(_bookPerson, _bookCurrentSpread);
}

function bookPrev() {
  if (_bookCurrentSpread <= 0) return;
  _bookCurrentSpread--;
  updateBookContent(_bookPerson, _bookCurrentSpread);
}

function briefSealHTML(person) {
  return '<div style="text-align:center;padding-bottom:16px;">' +
    '<svg width="52" height="52" viewBox="0 0 52 52">' +
      '<circle cx="26" cy="26" r="24" fill="#8B1A1A" stroke="#C8A84B" stroke-width="1.5"/>' +
      '<text x="26" y="31" text-anchor="middle" font-size="20" fill="#F5E6C8">⚓</text>' +
    '</svg>' +
    '<div style="margin-top:12px;">' +
      '<button onclick="returnToLog()" style="background:rgba(139,94,60,0.3);border:1px solid #8B5E3C;color:#3D1F0A;padding:7px 20px;border-radius:4px;font-family:Georgia,serif;font-size:13px;cursor:pointer;">← BACK TO LOG</button>' +
    '</div>' +
  '</div>';
}

function renderBrief(person, briefText) {
  var leftPage = document.getElementById('book-left-page');
  var rightPage = document.getElementById('book-right-page');

  leftPage.innerHTML =
    '<div class="book-brief-page" id="brief-left-content">' +
      '<div class="book-brief-title">CAPTAIN\'S BRIEF — @' + person.login + '</div>' +
      '<div class="book-brief-rule"></div>' +
      '<p id="brief-text-left" class="book-brief-text">' + briefText + '</p>' +
    '</div>';

  var textEl = document.getElementById('brief-text-left');
  var containerEl = document.getElementById('brief-left-content');

  if (textEl.scrollHeight > textEl.clientHeight) {
    var sentences = briefText.match(/[^.!?]+[.!?]+/g) || [briefText];
    var leftText = '';
    var rightText = '';
    for (var i = 0; i < sentences.length; i++) {
      leftText += sentences[i];
      textEl.textContent = leftText;
      if (textEl.scrollHeight > textEl.clientHeight) {
        leftText = sentences.slice(0, i).join('');
        rightText = sentences.slice(i).join('');
        break;
      }
    }
    document.getElementById('brief-text-left').innerHTML = leftText;
    rightPage.innerHTML =
      '<div class="book-brief-page">' +
        '<p class="book-brief-text">' + rightText + '</p>' +
        briefSealHTML(person) +
      '</div>';
  } else {
    rightPage.innerHTML =
      '<div class="book-brief-seal-page">' +
        briefSealHTML(person) +
      '</div>';
  }
}

function generateCrewBrief() {
  if (!_bookPerson) return;
  var leftPage = document.getElementById('book-left-page');
  var rightPage = document.getElementById('book-right-page');
  var prevBtn = document.getElementById('book-prev');
  var nextBtn = document.getElementById('book-next');
  if (prevBtn) prevBtn.style.display = 'none';
  if (nextBtn) nextBtn.style.display = 'none';

  if (leftPage) leftPage.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;font-family:Georgia,serif;font-style:italic;color:#8B6914;font-size:16px;">⚓ Consulting the watch...</div>';
  if (rightPage) rightPage.innerHTML = '';

  var person = _bookPerson;
  fetch('/api/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      owner: state.owner || 'parse-community',
      repo: state.repo || 'parse-server',
      system: 'You are a ship\'s captain writing a personal log entry addressed directly to a crew member about their security negligence.\nRules:\n- Address them by name (@' + person.login + ') in the first sentence\n- Name at least 3 specific packages by name with their exact days exposed\n- Call out BREAKING packages as unacceptable derelictions\n- Call out SAFE packages as inexcusable easy wins that were ignored\n- Give specific orders: exact package names and fix versions to ship\n- Naval tone: direct, authoritative, no corporate language\n- Write in exactly 2 paragraphs separated by a blank line\n- Paragraph 1: the damage — what they let happen and for how long\n- Paragraph 2: the orders — exactly what they must fix and in what priority\n- Under 130 words total. No bullet points. No generic advice.',
      messages: [{
        role: 'user',
        content: 'Write the captain\'s log entry for @' + person.login + '.\nTheir packages (ordered by severity):\n' +
          person.packages.map(function(p) {
            return '- ' + p.name + ': ' + (p.days_exposed || 0) + ' days exposed, ' + (p.actionability || 'BREAKING') + ', fix: ' + (p.version || '?') + ' → ' + (p.fix_version || '?');
          }).join('\n') +
          '\nTotal exposure: ' + (person.totalDays || 0) + ' days. Breaking count: ' + (person.breakingCount || 0) + '. Safe fixes ignored: ' + (person.safeIgnored || 0) + '.'
      }]
    })
  })
  .then(function(r) { return r.json(); })
  .then(function(data) {
    var response = (data && data.content) ? data.content : 'No intelligence received from the watch.';
    renderBrief(person, response);
  })
  .catch(function() {
    if (leftPage) leftPage.innerHTML = '<div style="padding:28px 24px;font-family:Georgia,serif;font-style:italic;color:#8B6914;">Signal lost — could not reach the intelligence layer.<br><br><button onclick="returnToLog()" style="background:rgba(139,94,60,0.3);border:1px solid #8B5E3C;color:#3D1F0A;padding:7px 18px;border-radius:4px;font-family:Georgia,serif;font-size:13px;cursor:pointer;">← BACK TO LOG</button></div>';
    if (rightPage) rightPage.innerHTML = '';
  });
}

function returnToLog() {
  updateBookContent(_bookPerson, _bookCurrentSpread);
}

// Wire up overlay click-to-close
document.addEventListener('DOMContentLoaded', function() {
  var overlay = document.getElementById('crew-book-overlay');
  if (overlay) overlay.addEventListener('click', function(e) {
    if (e.target === overlay) closeCrewBook();
  });
});


window.copyTicket = function(id, btn) {
  const text = document.getElementById(id).innerText;
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = '⚓ Copied!';
    btn.classList.add('copied');
    setTimeout(() => {
      btn.textContent = orig;
      btn.classList.remove('copied');
    }, 2000);
  }).catch(() => {
    btn.textContent = '? Copy failed';
    setTimeout(() => { btn.textContent = '? Copy to Clipboard'; }, 2000);
  });
};

function renderQueries(d) {
  const queries = [
    {
      name: 'SBOM Explosion',
      source: 'github',
      sql:
`SELECT json_get_str(pkg,'name')         AS name,
       json_get_str(pkg,'versionInfo')  AS version,
       json_get_str(json_get(pkg,'externalRefs',0),'referenceLocator') AS purl
FROM (SELECT unnest(json_get_array(sbom__packages)) AS pkg
      FROM github.sbom
      WHERE owner='${d.owner}' AND repo='${d.repo}')`,
      note: 'Unpacks the GitHub-generated SBOM (SPDX format) into one row per package. Native Coral table — no scraping, no rate-limit games.'
    },
    {
      name: 'Vulnerability Check',
      source: 'osv',
      sql:
`SELECT id, summary, published, affected, "references"
FROM osv.query_by_version
WHERE ecosystem='npm'
  AND package_name='braces'
  AND version='2.3.2'`,
      note: 'OSV requires constant filters — cannot dynamic-join. scan.py loops per package in Python while Coral handles the cross-source query.'
    },
    {
      name: 'Pre-CVE Canary',
      source: 'depsdev',
      sql:
`SELECT version, published_at, is_deprecated, deprecated_reason
FROM depsdev.package_versions
WHERE system='NPM'
  AND package_name='dompurify'
  AND is_deprecated=true`,
      note: 'When maintainers deprecate a release with "fixed a security issue" in the reason string, that\'s your warning before a CVE ever exists.'
    },
    {
      name: 'Ownership Mapping',
      source: 'github',
      sql:
`SELECT name, path, html_url
FROM github.search_code(q => 'repo:${d.owner}/${d.repo} postcss');

SELECT author_login, message
FROM github.search_commits(q => 'repo:${d.owner}/${d.repo} package.json');`,
      note: 'Cross-references which files import a vulnerable package with which engineers have touched dependency manifests. Bot accounts filtered downstream.'
    },
    {
      name: 'Active Exploitation',
      source: 'kev',
      sql:
`SELECT cve_id, vendor_project, product, vulnerability_name,
       date_added, known_ransomware_campaign_use
FROM kev.vulns
WHERE cve_id IN (SELECT cve_id FROM scan_results)`,
      note: 'CISA Known Exploited Vulnerabilities — if a CVE is on this list, it\'s being actively used in attacks. Custom Coral source contributed by this project.'
    },
  ];

  function colorize(sql) {
    const kws = /\b(SELECT|FROM|WHERE|AND|OR|JOIN|ON|AS|IN|GROUP|BY|ORDER|LIMIT|UNNEST|TRUE|FALSE|NULL)\b/g;
    const strs = /'[^']*'/g;
    const fns = /\b(json_get_str|json_get_array|json_get|unnest|count|sum|max|min|avg|coalesce)\b/g;
    let html = escape(sql);
    html = html.replace(strs, m => `<span class="str">${m}</span>`);
    html = html.replace(fns, m => `<span class="fn">${m}</span>`);
    html = html.replace(kws, m => `<span class="kw">${m}</span>`);
    html = html.replace(/\b(github|osv|depsdev|kev|npm|pypi|maven|scorecard)\.([a-z_]+)/g,
      '<span class="tbl">$1.$2</span>');
    return html;
  }

  document.getElementById('queriesList').innerHTML = queries.map(q => `
    <div class="query-card">
      <div class="query-head">
        <div class="query-name">${escape(q.name)}</div>
        <span class="source-badge ${q.source}">${q.source.toUpperCase()}</span>
      </div>
      <pre class="query-sql">${colorize(q.sql)}</pre>
      <div class="query-note">${escape(q.note)}</div>
    </div>
  `).join('');
}

// -- Urgency ring 
function urgencyRing(score) {
  const radius = 20;
  const circumference = 2 * Math.PI * radius;
  const filled = (score / 100) * circumference;
  const color = score >= 80 ? '#FF4444' : score >= 60 ? '#FF8C00' : score >= 40 ? '#4488FF' : '#00FF88';
  const glow = score >= 80 ? 'rgba(255,68,68,0.6)' : score >= 60 ? 'rgba(255,140,0,0.6)' : score >= 40 ? 'rgba(68,136,255,0.6)' : 'rgba(0,255,136,0.6)';
  const label = score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW';
  return `
    <div class="urgency-ring-wrap">
      <svg width="52" height="52" viewBox="0 0 52 52">
        <circle cx="26" cy="26" r="${radius}" fill="none"
                stroke="rgba(255,255,255,0.04)" stroke-width="4"/>
        <circle cx="26" cy="26" r="${radius}" fill="none"
                stroke="${color}" stroke-width="4"
                stroke-dasharray="${filled} ${circumference}"
                stroke-dashoffset="${circumference * 0.25}"
                stroke-linecap="round"
                transform="rotate(-90 26 26)"
                style="transition: stroke-dasharray 1s ease; filter: drop-shadow(0 0 6px ${glow})"/>
        <text x="26" y="30" text-anchor="middle"
              font-family="Space Mono, monospace" font-size="11"
              font-weight="700" fill="${color}">${score}</text>
      </svg>
      <div class="urgency-verdict" style="color:${color};text-shadow: 0 0 10px ${glow}">${label}</div>
    </div>`;
}

// -- Radar blip spawning 
let blipInterval = null;
function spawnRadarBlip() {
  const container = document.getElementById('radar-blips');
  if (!container) return;
  const angle = Math.random() * 360;
  const dist = 20 + Math.random() * 120;
  const rad = (angle * Math.PI) / 180;
  const x = 150 + dist * Math.cos(rad);
  const y = 150 + dist * Math.sin(rad);
  const blip = document.createElement('div');
  blip.className = 'radar-blip';
  blip.style.left = x + 'px';
  blip.style.top = y + 'px';
  const danger = Math.random() > 0.7;
  blip.style.background = danger ? '#ef4444' : '#E8C55A';
  blip.style.boxShadow = `0 0 8px ${danger ? '#ef4444' : '#E8C55A'}`;
  container.appendChild(blip);
  setTimeout(() => blip.remove(), 2000);
}
function startRadarBlips() { if (!blipInterval) blipInterval = setInterval(spawnRadarBlip, 400); }
function stopRadarBlips() { clearInterval(blipInterval); blipInterval = null; }

function showRadarOverlay(owner, repo) {
  document.getElementById('radar-repo').textContent = owner + '/' + repo;
  document.getElementById('radar-message').textContent = 'Charting the waters...';
  document.getElementById('radar-progress-fill').style.width = '0%';
  document.getElementById('radar-progress-pct').textContent = '0%';
  document.getElementById('radar-overlay').classList.add('show');
  startRadarBlips();
}
function updateRadarOverlay(message, pct) {
  if (message) document.getElementById('radar-message').textContent = message;
  if (typeof pct === 'number') {
    document.getElementById('radar-progress-fill').style.width = pct + '%';
    document.getElementById('radar-progress-pct').textContent = pct + '%';
  }
}
function hideRadarOverlay() {
  document.getElementById('radar-overlay').classList.remove('show');
  stopRadarBlips();
}

// -- Animations 
function animateCountUp(el, target, duration) {
  const start = performance.now();
  const startVal = 0;
  function tick(now) {
    const t = Math.min(1, (now - start) / duration);
    const eased = 1 - Math.pow(1 - t, 3);
    el.textContent = Math.round(startVal + (target - startVal) * eased).toLocaleString();
    if (t < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

// -- Scan flow 
function displayScanError(errorMsg) {
  const sbomErrors = ['sbom', 'dependency graph', 'timed out', '500'];
  const isSbomError = sbomErrors.some(e =>
    (errorMsg || '').toLowerCase().includes(e)
  );
  if (isSbomError) {
    const owner = state.owner || 'OWNER';
    const repo = state.repo || 'REPO';
    return errorMsg +
      '\n\nTip: Enable GitHub dependency graph at: ' +
      'github.com/' + owner + '/' + repo + '/settings/security_analysis\n' +
      'Or try one of our demo repos: parse-community/parse-server, ' +
      'apache/logging-log4j2, django/django';
  }
  return errorMsg;
}

async function startScan(ev) {
  ev.preventDefault();
  const val = document.getElementById('repoInput').value.trim();
  if (!val.includes('/')) {
    showToast('Use format: owner/repo');
    return false;
  }
  const [owner, repo] = val.split('/').map(s => s.trim());
  state.owner = owner;
  state.repo = repo;
  syncRepoInputs(owner + '/' + repo);
  hideLaunch();

  document.getElementById('scanBtn').disabled = true;
  showRadarOverlay(owner, repo);
  updateRadarOverlay('Charting latest Coral course…', 1);

  try {
    const r = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ owner, repo, mode: state.scanMode }),
    });
    if (!r.ok) throw new Error(`Scan kickoff failed: HTTP ${r.status}`);
    const scanStarted = await r.json();
    const { job_id } = scanStarted;
    if (scanStarted.owner && scanStarted.repo) {
      state.owner = scanStarted.owner;
      state.repo = scanStarted.repo;
      syncRepoInputs(state.owner + '/' + state.repo);
    }
    state.scanMode = scanStarted.mode || state.scanMode;
    state.jobId = job_id;
    pollJob(job_id);
  } catch (e) {
    hideRadarOverlay();
    document.getElementById('scanBtn').disabled = false;
    showToast(displayScanError('Scan failed to start: ' + e.message));
  }
  return false;
}

function nauticalMsg(pct) {
  if (pct < 30) return 'Charting the waters — fetching SBOM…';
  if (pct < 60) return 'Scanning the depths — checking OSV vulnerabilities…';
  if (pct < 85) return 'Running canary sweep — checking deps.dev…';
  if (pct < 100) return 'Mapping the crew — tracing ownership…';
  return 'All hazards charted ⚓';
}

async function pollJob(jobId) {
  try {
    const r = await fetch(`/api/status/${jobId}`);
    if (!r.ok) throw new Error('Status poll failed');
    const j = await r.json();
    updateRadarOverlay(j.message || nauticalMsg(j.progress), j.progress);

    if (j.status === 'complete') {
      updateRadarOverlay('All hazards charted ⚓', 100);
      setTimeout(async () => {
        hideRadarOverlay();
        document.getElementById('scanBtn').disabled = false;
        try {
          const data = await fetchResults(state.owner, state.repo, false);
          state.data = data;
          renderAll();
          showScreen('askwatch', document.getElementById('navAskWatch'));
          setLiveStatus(`LIVE CORAL · latest scan · ${new Date().toLocaleTimeString()}`);
        } catch (e) {
          showToast(displayScanError('Scan complete but results fetch failed: ' + e.message));
        }
      }, 600);
    } else if (j.status === 'error') {
      hideRadarOverlay();
      document.getElementById('scanBtn').disabled = false;
      showToast(displayScanError('Scan error: ' + (j.error || j.message)));
    } else {
      setTimeout(() => pollJob(jobId), 2000);
    }
  } catch (e) {
    hideRadarOverlay();
    document.getElementById('scanBtn').disabled = false;
    showToast(displayScanError('Polling failed: ' + e.message));
  }
}

// -- UI utilities 
function showProgress(msg, pct) {
  document.getElementById('progressOverlay').classList.add('show');
  document.getElementById('progressMsg').textContent = msg;
  document.getElementById('progressFill').style.width = pct + '%';
  document.getElementById('progressPct').textContent = pct + '%';
}
function hideProgress() {
  document.getElementById('progressOverlay').classList.remove('show');
}
function showToast(msg) {
  document.getElementById('toastMsg').textContent = msg;
  document.getElementById('toast').classList.add('show');
}
function hideToast() {
  document.getElementById('toast').classList.remove('show');
}
function setLiveStatus(s) {
  document.getElementById('liveStatus').textContent = s;
}

// -- Boot
(async function init() {
  window.currentData = { owner: state.owner, repo: state.repo, scan: [], sweep: {}, ownership: [] };
  setLiveStatus('LIVE CORAL · ask to investigate');
  if (typeof window.initWatchOnNav === 'function') window.initWatchOnNav();
  try {
    const data = await fetchResults(state.owner, state.repo, false);
    state.data = data;
    state.owner = data.owner;
    state.repo = data.repo;
    renderAll();
    setLiveStatus(`LIVE CORAL · scan snapshot · ${new Date().toLocaleTimeString()}`);
  } catch (e) {
    window.currentData = { owner: state.owner, repo: state.repo, scan: [], sweep: {}, ownership: [] };
    setLiveStatus('LIVE CORAL · ask to investigate');
    if (typeof window.initWatchOnNav === 'function') window.initWatchOnNav();
  }
})();


// -- Ask the Watch 
(function() {
  let watchHistory = [];
  let watchInitialized = false;
  let watchCurrentRepo = null;

  function getData() { return window.currentData || null; }
  function repoKey() {
    const d = getData();
    return d ? (d.owner + '/' + d.repo) : null;
  }
  function maybeResetForNewRepo() {
    const r = repoKey();
    if (r && r !== watchCurrentRepo) {
      watchCurrentRepo = r;
      watchHistory = [];
      watchInitialized = false;
    }
  }

  function escapeHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c => (
      {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]
    ));
  }

  function buildGreetingText() {
    const d = getData();
    if (!d) {
      return 'WATCH ONLINE\nLive Coral investigation is ready for ' + state.owner + '/' + state.repo + '.\nAsk what an attacker would look at first, what to patch this week, or who owns a risky dependency.';
    }
    const scan = d.scan || [];
    const N = scan.length;
    const X = scan.reduce((m, p) => Math.max(m, p.worst_days_exposed || 0), 0);
    const ownerSet = new Set();
    (d.ownership || []).forEach(o => {
      (o.owners || []).forEach(name => {
        if (!/\[bot\]/i.test(name)) ownerSet.add(name);
      });
    });
    const Y = ownerSet.size;
    return '⚓ WATCH OFFICER ONLINE\n'
         + 'Intelligence loaded: ' + d.owner + '/' + d.repo + '\n'
         + N + ' vulnerable packages · ' + X + ' days worst exposure · ' + Y + ' crew members identified\n'
         + 'Ask me a real incident-review question. I will show the Coral evidence trace.';
  }

  function makeBubble(role, text) {
    const wrap = document.createElement('div');
    wrap.className = 'atw-bubble atw-bubble-' + (role === 'user' ? 'user' : 'assistant');
    const label = document.createElement('span');
    label.className = 'atw-bubble-label';
    label.textContent = role === 'user' ? 'YOU ·' : '⚓ WATCH ·';
    const body = document.createElement('div');
    body.className = 'atw-bubble-body';
    body.innerHTML = escapeHtml(text).replace(/\n/g, '<br>');
    wrap.appendChild(label);
    wrap.appendChild(body);
    return wrap;
  }

  function makeInvestigationBubble(data) {
    const wrap = document.createElement('div');
    wrap.className = 'atw-bubble atw-bubble-assistant';
    const label = document.createElement('span');
    label.className = 'atw-bubble-label';
    label.textContent = 'WATCH · LIVE CORAL';
    const body = document.createElement('div');
    body.className = 'atw-bubble-body';
    const evidence = Array.isArray(data.evidence) ? data.evidence : [];
    const actions = Array.isArray(data.recommended_actions) ? data.recommended_actions : [];
    const sources = Array.isArray(data.sources_used) ? data.sources_used : [];
    const queries = Array.isArray(data.coral_queries) ? data.coral_queries : [];

    function evidenceCard(item) {
      const title = item.package || item.cve || item.upstream_repo || 'Evidence';
      const rows = Object.keys(item).filter(k => k !== 'package').map(k => {
        let value = item[k];
        if (Array.isArray(value)) value = value.map(v => typeof v === 'object' ? JSON.stringify(v) : v).join(', ');
        if (value && typeof value === 'object') value = JSON.stringify(value);
        return '<div class="atw-kv"><span>' + escapeHtml(k.replace(/_/g, ' ')) + '</span><span>' + escapeHtml(value || 'n/a') + '</span></div>';
      }).join('');
      return '<div class="atw-evidence-card"><strong>' + escapeHtml(title) + '</strong>' + rows + '</div>';
    }

    body.innerHTML =
      '<div class="atw-answer">' +
        '<div><div class="atw-answer-title">Verdict</div><div class="atw-verdict">' + escapeHtml(data.verdict || data.content || 'Investigation complete.') + '</div></div>' +
        '<div>' + escapeHtml(data.content || '').replace(/\n/g, '<br>') + '</div>' +
        (evidence.length ? '<div><div class="atw-answer-title">Evidence</div><div class="atw-evidence-grid">' + evidence.map(evidenceCard).join('') + '</div></div>' : '') +
        (actions.length ? '<div><div class="atw-answer-title">Recommended Actions</div><ul class="atw-actions">' + actions.map(a => '<li>' + escapeHtml(a) + '</li>').join('') + '</ul></div>' : '') +
        '<details class="atw-trace"><summary>Coral evidence trace · ' + sources.length + ' sources · confidence ' + escapeHtml(data.confidence || 'unknown') + '</summary>' +
          (data.candidate_source ? '<div class="atw-query">candidate set: ' + escapeHtml(data.candidate_source) + '</div>' : '') +
          '<div class="atw-source-list">' + sources.map(s => '<span class="atw-source-chip">' + escapeHtml(s) + '</span>').join('') + '</div>' +
          queries.map(q => '<div class="atw-query">' + escapeHtml(q) + '</div>').join('') +
        '</details>' +
      '</div>';
    wrap.appendChild(label);
    wrap.appendChild(body);
    return wrap;
  }

  function addBubble(role, text) {
    const container = document.getElementById('watchChatMessages');
    if (!container) return;
    container.appendChild(makeBubble(role, text));
    container.scrollTop = container.scrollHeight;
  }

  function addInvestigationBubble(data) {
    const container = document.getElementById('watchChatMessages');
    if (!container) return;
    container.appendChild(makeInvestigationBubble(data));
    container.scrollTop = container.scrollHeight;
  }

  function addThinkingBubble() {
    const container = document.getElementById('watchChatMessages');
    if (!container) return;
    const wrap = document.createElement('div');
    wrap.className = 'atw-bubble atw-bubble-assistant atw-bubble-thinking';
    wrap.id = 'watchThinking';
    const label = document.createElement('span');
    label.className = 'atw-bubble-label';
    label.textContent = '⚓ WATCH ·';
    const dots = document.createElement('div');
    dots.className = 'atw-thinking-dots';
    dots.innerHTML = '<span>•</span><span>•</span><span>•</span>';
    wrap.appendChild(label);
    wrap.appendChild(dots);
    container.appendChild(wrap);
    container.scrollTop = container.scrollHeight;
  }

  function removeThinkingBubble() {
    const el = document.getElementById('watchThinking');
    if (el) el.remove();
  }

  function renderGreeting() {
    const container = document.getElementById('watchChatMessages');
    if (!container) return;
    container.innerHTML = '';
    container.appendChild(makeBubble('assistant', buildGreetingText()));
  }

  function buildSystemPrompt() {
    const d = getData();
    if (!d) {
      return 'You are the Watch Officer of DriftWatch. No repository intelligence is currently loaded. Ask the user to load a repository first before answering any questions.';
    }
    const owner = d.owner;
    const repo = d.repo;
    const scan = d.scan || [];
    const sweep = d.sweep || {};
    const ownership = d.ownership || [];

    // Package name → owner logins
    const ownerMap = {};
    ownership.forEach(o => {
      ownerMap[String(o.package || '').toLowerCase()] = (o.owners || []).filter(n => !/\[bot\]/i.test(n));
    });

    // Most-severe upgrade row per package
    const upgradeMap = {};
    (sweep.upgrade_actionability || []).forEach(u => {
      const k = u.name;
      if (!upgradeMap[k] || (u.days_exposed || 0) > (upgradeMap[k].days_exposed || 0)) {
        upgradeMap[k] = u;
      }
    });

    const pkgLines = scan.map(p => {
      const days = p.worst_days_exposed || 0;
      const cveCount = (p.cves || []).length;
      const ug = upgradeMap[p.name];
      const fix = (ug && ug.fixed_version) || (p.cves && p.cves[0] && p.cves[0].fixed_in) || '?';
      const action = (ug && ug.actionability) || 'BREAKING';
      const owners = ownerMap[String(p.name).toLowerCase()] || [];
      const ownerStr = owners.length ? owners.join(', ') : 'unowned';
      return '- ' + p.name + ' v' + (p.version || '?') + ': ' + days + 'd exposed, ' + cveCount + ' CVEs, ' + action + ' fix → ' + fix + ', owners: ' + ownerStr;
    }).join('\n');

    const crewMap = {};
    ownership.forEach(o => {
      (o.owners || []).filter(n => !/\[bot\]/i.test(n)).forEach(name => {
        if (!crewMap[name]) crewMap[name] = [];
        crewMap[name].push(o.package);
      });
    });
    const ownerLines = Object.keys(crewMap).map(n => '- @' + n + ': responsible for ' + crewMap[n].join(', ')).join('\n');

    const preCve = (sweep.pre_cve_findings || []).filter(f => f.has_security_deprecation);
    const preCveLines = preCve.length
      ? preCve.map(f => {
          const dep = (f.security_deprecations && f.security_deprecations[0]) || {};
          return '- ' + f.name + ' v' + (f.installed_version || '?') + ': deprecated ' + (dep.days_ago != null ? dep.days_ago + 'd' : '?') + ' ago — "' + (dep.reason || '') + '"';
        }).join('\n')
      : 'None detected';

    return 'You are the Watch Officer of DriftWatch — a supply-chain security intelligence agent. You are speaking to a security engineer about the repository ' + owner + '/' + repo + '.\n\n'
         + 'Speak with the authority of a ship\'s navigator: precise, urgent, no filler. Use nautical metaphors sparingly and only when they land naturally. Always end your response with one concrete recommended action.\n\n'
         + 'You have full intelligence on this repository:\n\n'
         + 'VULNERABLE PACKAGES (' + scan.length + ' total):\n'
         + (pkgLines || '(none)') + '\n\n'
         + 'CREW ACCOUNTABILITY:\n'
         + (ownerLines || '(none mapped)') + '\n\n'
         + 'PRE-CVE SIGNALS:\n'
         + preCveLines + '\n\n'
         + 'Answer questions about risk, ownership, prioritization, and remediation using only this data. Be specific with names, numbers, and days. Never make up data not in the above.';
  }

  async function sendMessage() {
    const input = document.getElementById('watchInput');
    const btn = document.getElementById('watchSendBtn');
    if (!input || !btn) return;
    const text = input.value.trim();
    if (!text) return;

    if (false && !getData()) {
      addBubble('assistant', 'Load a repository first — I need intelligence data before I can chart a course.');
      return;
    }

    maybeResetForNewRepo();

    addBubble('user', text);
    input.value = '';
    input.disabled = true;
    btn.disabled = true;
    addThinkingBubble();

    watchHistory.push({ role: 'user', content: text });

    try {
      const repoText = (document.getElementById('repoInput')?.value || (state.owner + '/' + state.repo)).trim();
      const parts = repoText.split('/');
      const owner = (parts[0] || state.owner || 'jellyfin').trim();
      const repo = (parts[1] || state.repo || 'jellyfin-web').trim();
      state.owner = owner;
      state.repo = repo;
      const response = await fetch("/api/investigate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          owner: owner,
          repo: repo,
          question: text
        })
      });
      const data = await response.json();
      removeThinkingBubble();
      if (!response.ok) {
        const detail = data && data.detail ? data.detail : 'Unknown backend error';
        const msg = typeof detail === 'string'
          ? detail
          : (detail.error && detail.error.message) || JSON.stringify(detail);
        addBubble('assistant', '⚠  Signal lost — ' + msg);
      } else if (!data || !data.content) {
        addBubble('assistant', '⚠  Signal lost — no answer came back from the intelligence layer.');
      } else {
        const reply = data.content;
        watchHistory.push({ role: 'assistant', content: reply });
        try {
          addInvestigationBubble(data);
        } catch (renderError) {
          addBubble('assistant', reply + '\n\nRender fallback: ' + renderError.message);
        }
      }
    } catch (e) {
      removeThinkingBubble();
      addBubble('assistant', 'Signal lost - ' + (e && e.message ? e.message : 'could not reach the intelligence layer.'));
    } finally {
      input.disabled = false;
      btn.disabled = false;
      input.focus();
    }
  }

  function wire() {
    document.querySelectorAll('#watchPills .atw-pill').forEach(p => {
      p.addEventListener('click', () => {
        const input = document.getElementById('watchInput');
        if (input) { input.value = p.textContent.trim(); input.focus(); }
      });
    });
    const btn = document.getElementById('watchSendBtn');
    if (btn) btn.addEventListener('click', sendMessage);
    const input = document.getElementById('watchInput');
    if (input) input.addEventListener('keydown', e => {
      if (e.key === 'Enter') { e.preventDefault(); sendMessage(); }
    });
    renderGreeting();
  }

  // Screen activation hook — called from the navAskWatch click listener above
  window.initWatchOnNav = function() {
    const r = repoKey();
    if (r && r !== watchCurrentRepo) {
      // New repo loaded since last visit — wipe state and re-greet
      watchCurrentRepo = r;
      watchHistory = [];
      watchInitialized = false;
    }
    if (getData() && !watchInitialized) {
      renderGreeting();
      watchInitialized = true;
    }
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', wire);
  } else {
    wire();
  }
})();


(function() {
  var parrot = document.getElementById('sidebarParrot');
  var bubble = document.getElementById('parrotBubble');
  if (!parrot || !bubble) return;
  var hideTimer = null;
  parrot.addEventListener('click', function() {
    var n = (window.currentData && Array.isArray(window.currentData.scan))
      ? window.currentData.scan.length
      : 'unknown';
    bubble.textContent = 'Squawk! ' + n + ' hazards in these waters! ⚓';
    bubble.classList.add('visible');
    if (hideTimer) clearTimeout(hideTimer);
    hideTimer = setTimeout(function() {
      bubble.classList.remove('visible');
    }, 3000);
  });
})();

