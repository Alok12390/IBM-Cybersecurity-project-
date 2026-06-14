// Tab switching
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
  });
});

// Input mode toggle
document.querySelectorAll('.mode-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const mode = btn.dataset.mode;
    document.getElementById('field-mode').style.display = mode === 'fields' ? 'block' : 'none';
    document.getElementById('raw-mode').style.display = mode === 'raw' ? 'block' : 'none';
  });
});

// Sample data
const SAMPLES = {
  phishing: {
    sender: 'support@paypa1-security.tk',
    subject: 'URGENT: Your Account Has Been Suspended! VERIFY NOW',
    body: `Dear Valued Customer,

We detected unusual activity on your account. Your account will be CLOSED in 24 hours unless you verify your identity IMMEDIATELY.

Click here to verify your account and prevent suspension:
http://bit.ly/3xVerifyPaypal-secure-login.xyz/account/verify?user=victim@email.com

Act now to avoid losing access. This is your FINAL WARNING.

You must confirm your email and update your payment information to continue using our services.

Best regards,
PayPal Security Team
© 2024 PayPal Inc.`
  },
  legit: {
    sender: 'newsletter@github.com',
    subject: 'Your monthly GitHub Activity Summary for June',
    body: `Hi there,

Here is your GitHub activity summary for the month of June 2024.

Repositories contributed to: 8
Pull requests opened: 12
Issues closed: 5
Stars received: 34

You can view your full contribution graph at https://github.com/your-username

Thanks for being part of the GitHub community.

— The GitHub Team
https://github.com`
  }
};

function loadSample(type) {
  const s = SAMPLES[type];
  document.getElementById('email-sender').value = s.sender;
  document.getElementById('email-subject').value = s.subject;
  document.getElementById('email-body').value = s.body;
  // Ensure field mode is active
  document.querySelectorAll('.mode-btn')[0].click();
}

// Render severity badge
function sevBadge(sev) {
  return `<span class="finding-sev sev-${sev}">${sev}</span>`;
}

// Render finding item (generic)
function renderFindingLi(text, icon = '•') {
  const isGood = text.startsWith('✓') || text.includes('passed') || text.includes('valid');
  return `<li>
    <span class="finding-icon">${isGood ? '✅' : '⚠️'}</span>
    <span>${escHtml(text)}</span>
  </li>`;
}

function renderVulnFinding(f) {
  return `<li>
    ${sevBadge(f.severity)}
    <div class="finding-content">
      <div class="finding-issue">${escHtml(f.issue)}</div>
      ${f.detail ? `<div class="finding-detail">${escHtml(f.detail)}</div>` : ''}
    </div>
  </li>`;
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function setScore(scoreEl, fillEl, badgeEl, score, level) {
  scoreEl.textContent = score;
  scoreEl.style.color = {Low:'#3fb950', Medium:'#e3b341', High:'#d29922', Critical:'#da3633'}[level] || '#e6edf3';
  fillEl.style.width = score + '%';
  fillEl.className = 'score-fill ' + level;
  badgeEl.textContent = level;
  badgeEl.className = 'risk-badge ' + level;
}

// ===================== EMAIL ANALYZER =====================
async function analyzeEmail() {
  const btn = document.getElementById('btn-analyze-email');
  btn.querySelector('.btn-text').style.display = 'none';
  btn.querySelector('.btn-spinner').style.display = 'inline';
  btn.disabled = true;

  const activeMode = document.querySelector('.mode-btn.active')?.dataset.mode || 'fields';
  const payload = activeMode === 'raw'
    ? { raw_email: document.getElementById('email-raw').value }
    : {
        sender: document.getElementById('email-sender').value,
        subject: document.getElementById('email-subject').value,
        body: document.getElementById('email-body').value,
      };

  try {
    const resp = await fetch('/api/analyze-email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();
    renderEmailResults(data);
  } catch (e) {
    alert('Error connecting to server: ' + e.message);
  } finally {
    btn.querySelector('.btn-text').style.display = 'inline';
    btn.querySelector('.btn-spinner').style.display = 'none';
    btn.disabled = false;
  }
}

function renderEmailResults(data) {
  document.getElementById('email-placeholder').style.display = 'none';
  const card = document.getElementById('email-results');
  card.style.display = 'block';

  setScore(
    document.getElementById('email-score'),
    document.getElementById('email-score-fill'),
    document.getElementById('email-risk-badge'),
    data.score, data.risk_level
  );
  document.getElementById('email-summary').textContent = data.summary;

  // Key findings
  const fl = document.getElementById('email-findings-list');
  fl.innerHTML = '';
  (data.findings || []).forEach(f => { fl.innerHTML += renderFindingLi(f); });
  document.getElementById('email-findings-section').style.display =
    data.findings?.length ? 'block' : 'none';

  // Keywords
  const kChips = document.getElementById('email-keyword-chips');
  kChips.innerHTML = '';
  if (data.keyword_hits?.length) {
    data.keyword_hits.forEach(k => {
      kChips.innerHTML += `<span class="keyword-chip">${escHtml(k)}</span>`;
    });
    document.getElementById('email-keywords-section').style.display = 'block';
  } else {
    document.getElementById('email-keywords-section').style.display = 'none';
  }

  // URLs
  const urlDetails = document.getElementById('email-url-details');
  urlDetails.innerHTML = '';
  if (data.url_analysis?.length) {
    data.url_analysis.forEach(u => {
      const issueHtml = (u.issues || []).map(i =>
        `<div class="url-issue">⚠ ${escHtml(i)}</div>`
      ).join('');
      urlDetails.innerHTML += `
        <div class="url-item">
          <div class="url-item-url">${escHtml(u.url)}</div>
          ${issueHtml}
          <div class="url-risk-score">URL risk score: ${u.risk}/100</div>
        </div>`;
    });
    document.getElementById('email-urls-section').style.display = 'block';
  } else {
    document.getElementById('email-urls-section').style.display = 'none';
  }

  // Header analysis
  const hl = document.getElementById('email-header-list');
  hl.innerHTML = '';
  if (data.header_analysis?.length) {
    data.header_analysis.forEach(h => { hl.innerHTML += renderFindingLi(h); });
    document.getElementById('email-headers-section').style.display = 'block';
  } else {
    document.getElementById('email-headers-section').style.display = 'none';
  }
}

// ===================== VULNERABILITY SCANNER =====================
async function scanVuln() {
  const url = document.getElementById('vuln-url').value.trim();
  if (!url) { alert('Please enter a URL to scan.'); return; }

  const btn = document.getElementById('btn-analyze-vuln');
  btn.querySelector('.btn-text').style.display = 'none';
  btn.querySelector('.btn-spinner').style.display = 'inline';
  btn.disabled = true;

  try {
    const resp = await fetch('/api/scan-url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    const data = await resp.json();
    if (data.error) { alert('Scan error: ' + data.error); return; }
    renderVulnResults(data);
  } catch (e) {
    alert('Error: ' + e.message);
  } finally {
    btn.querySelector('.btn-text').style.display = 'inline';
    btn.querySelector('.btn-spinner').style.display = 'none';
    btn.disabled = false;
  }
}

function renderVulnResults(data) {
  document.getElementById('vuln-placeholder').style.display = 'none';
  const card = document.getElementById('vuln-results');
  card.style.display = 'block';

  setScore(
    document.getElementById('vuln-score'),
    document.getElementById('vuln-score-fill'),
    document.getElementById('vuln-risk-badge'),
    data.score, data.risk_level
  );
  document.getElementById('vuln-summary').textContent = data.summary;

  const sections = [
    { listId: 'vuln-ssl-list',    items: data.ssl_findings },
    { listId: 'vuln-header-list', items: data.header_findings },
    { listId: 'vuln-path-list',   items: data.path_findings },
    { listId: 'vuln-port-list',   items: data.port_findings },
  ];

  sections.forEach(({ listId, items }) => {
    const el = document.getElementById(listId);
    el.innerHTML = '';
    (items || []).forEach(f => { el.innerHTML += renderVulnFinding(f); });
    if (!items?.length) {
      el.innerHTML = '<li><span class="finding-icon">✅</span><span>No issues detected</span></li>';
    }
  });
}
