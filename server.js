const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;

const DATA_DIR = process.env.VERCEL ? '/tmp' : __dirname;
const APPROVED_FILE = path.join(DATA_DIR, 'approved.json');
const PENDING_FILE = path.join(DATA_DIR, 'pending.json');

const RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000; // 10 minutes
const RATE_LIMIT_MAX_SUBMISSIONS = 5;
const submissionHits = new Map();

const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'change-this-password';

app.use(express.json({ limit: '100kb' }));

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  next();
});

function readJsonArray(filePath) {
  try {
    if (!fs.existsSync(filePath)) return [];
    const raw = fs.readFileSync(filePath, 'utf8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    console.error(`Failed reading ${filePath}:`, err.message);
    return [];
  }
}

function writeJsonArray(filePath, value) {
  try {
    fs.writeFileSync(filePath, JSON.stringify(value, null, 2), 'utf8');
    return true;
  } catch (err) {
    console.error(`Failed writing ${filePath}:`, err.message);
    return false;
  }
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function cleanText(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function parseHowField(sig) {
  const how = cleanText(sig?.access?.how);
  if (!how) {
    return { fallbackContact: '', fallbackNote: '' };
  }
  const parts = how.split('|').map((part) => part.trim()).filter(Boolean);
  if (!parts.length) {
    return { fallbackContact: '', fallbackNote: '' };
  }
  if (parts.length === 1) {
    const single = parts[0];
    if (single.toLowerCase() === 'user submission') {
      return { fallbackContact: '', fallbackNote: '' };
    }
    return { fallbackContact: '', fallbackNote: single };
  }
  return {
    fallbackContact: parts[0],
    fallbackNote: parts.slice(1).join(' | ')
  };
}

function describeSignal(sig) {
  const title = cleanText(sig?.title) || 'Untitled signal';

  const startDate = new Date(sig?.startTime || '');
  const when = Number.isNaN(startDate.getTime())
    ? 'Not provided'
    : startDate.toLocaleString('en-US', {
      dateStyle: 'medium',
      timeStyle: 'short'
    });

  const placeText = cleanText(sig?.access?.place) || cleanText(sig?.location);
  const lat = Number.parseFloat(sig?.lat);
  const lon = Number.parseFloat(sig?.lon);
  const hasCoords = Number.isFinite(lat) && Number.isFinite(lon);
  const where = placeText || (hasCoords ? `${lat.toFixed(5)}, ${lon.toFixed(5)}` : 'Not provided');
  const mapHref = hasCoords ? `https://www.google.com/maps?q=${encodeURIComponent(`${lat},${lon}`)}` : '';

  const { fallbackContact, fallbackNote } = parseHowField(sig);
  const contact = cleanText(sig?.contact) || fallbackContact || 'Not provided';
  const notes = cleanText(sig?.note) || fallbackNote || 'Not provided';
  const topic = cleanText(sig?.topic) || 'Not provided';

  const submittedDate = new Date(sig?.submittedAt || '');
  const submitted = Number.isNaN(submittedDate.getTime())
    ? 'Unknown'
    : submittedDate.toLocaleString('en-US', {
      dateStyle: 'medium',
      timeStyle: 'short'
    });

  return {
    id: String(sig?.id || ''),
    title,
    when,
    where,
    contact,
    notes,
    topic,
    submitted,
    hasCoords,
    mapHref,
    rawJson: JSON.stringify(sig, null, 2)
  };
}

function safeEqual(a, b) {
  const aBuf = Buffer.from(String(a));
  const bBuf = Buffer.from(String(b));
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function parseBasicAuth(req) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Basic ')) return null;
  try {
    const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
    const idx = decoded.indexOf(':');
    if (idx === -1) return null;
    return {
      user: decoded.slice(0, idx),
      pass: decoded.slice(idx + 1)
    };
  } catch (err) {
    return null;
  }
}

function requireAdmin(req, res, next) {
  const creds = parseBasicAuth(req);
  const isAuthed = creds
    && safeEqual(creds.user, ADMIN_USER)
    && safeEqual(creds.pass, ADMIN_PASS);

  if (!isAuthed) {
    res.setHeader('WWW-Authenticate', 'Basic realm="BX Signal Admin"');
    return res.status(401).send('Admin authentication required');
  }
  next();
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim()) {
    return forwarded.split(',')[0].trim();
  }
  return req.socket?.remoteAddress || 'unknown';
}

function enforceSubmissionRateLimit(req, res, next) {
  const ip = getClientIp(req);
  const now = Date.now();
  const recent = (submissionHits.get(ip) || []).filter((ts) => now - ts <= RATE_LIMIT_WINDOW_MS);

  if (recent.length >= RATE_LIMIT_MAX_SUBMISSIONS) {
    const retryAfterSec = Math.max(1, Math.ceil((RATE_LIMIT_WINDOW_MS - (now - recent[0])) / 1000));
    res.setHeader('Retry-After', String(retryAfterSec));
    return res.status(429).json({
      success: false,
      message: `Too many submissions. Try again in ${retryAfterSec} seconds.`
    });
  }

  recent.push(now);
  submissionHits.set(ip, recent);
  next();
}

function validateIncomingSignal(payload) {
  if (!payload || typeof payload !== 'object') {
    return { ok: false, message: 'Invalid payload' };
  }

  const title = typeof payload.title === 'string' ? payload.title.trim() : '';
  const startTime = typeof payload.startTime === 'string' ? payload.startTime.trim() : '';

  if (!title) {
    return { ok: false, message: 'Missing title' };
  }
  if (!startTime || Number.isNaN(new Date(startTime).getTime())) {
    return { ok: false, message: 'Missing or invalid startTime' };
  }

  return { ok: true };
}

// Get approved signals (for the map)
app.get('/api/signals', (req, res) => {
  const approved = readJsonArray(APPROVED_FILE);
  res.json(approved);
});

// Add new signal to pending
app.post('/api/signals', enforceSubmissionRateLimit, (req, res) => {
  const incoming = req.body;
  const validation = validateIncomingSignal(incoming);
  if (!validation.ok) {
    return res.status(400).json({ success: false, message: validation.message });
  }

  const pending = readJsonArray(PENDING_FILE);

  const newSignal = {
    ...incoming,
    id: incoming.id && typeof incoming.id === 'string'
      ? incoming.id
      : `sig-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
    status: 'pending',
    submittedAt: new Date().toISOString()
  };

  pending.push(newSignal);

  const saved = writeJsonArray(PENDING_FILE, pending);
  if (!saved) {
    return res.status(500).json({ success: false, message: 'Could not save pending signal' });
  }

  res.status(201).json({
    success: true,
    message: 'Signal submitted for review!',
    id: newSignal.id
  });
});

// Admin page to review pending (Basic Auth protected)
app.get('/admin', requireAdmin, (req, res) => {
  const pending = readJsonArray(PENDING_FILE);
  const approvedCount = readJsonArray(APPROVED_FILE).length;

  let cards = '';
  pending.forEach((sig) => {
    const info = describeSignal(sig);
    const encodedId = encodeURIComponent(info.id);
    const mapLine = info.hasCoords
      ? `<a href="${info.mapHref}" target="_blank" rel="noopener">Open map location</a>`
      : '<span class="dim">No coordinates provided</span>';

    cards += `
      <article class="card">
        <header class="card-head">
          <h3>${escapeHtml(info.title)}</h3>
          <code>${escapeHtml(info.id || 'missing-id')}</code>
        </header>
        <dl class="meta">
          <div><dt>What</dt><dd>${escapeHtml(info.title)}</dd></div>
          <div><dt>When</dt><dd>${escapeHtml(info.when)}</dd></div>
          <div><dt>Where</dt><dd>${escapeHtml(info.where)}<br>${mapLine}</dd></div>
          <div><dt>Who / Contact</dt><dd>${escapeHtml(info.contact)}</dd></div>
          <div><dt>Notes</dt><dd>${escapeHtml(info.notes)}</dd></div>
          <div><dt>Topic</dt><dd>${escapeHtml(info.topic)}</dd></div>
          <div><dt>Submitted</dt><dd>${escapeHtml(info.submitted)}</dd></div>
        </dl>
        <details>
          <summary>Show raw request data</summary>
          <pre>${escapeHtml(info.rawJson)}</pre>
        </details>
        <div class="actions">
          <button class="approve" onclick="approveById('${encodedId}')">Approve (shows on map)</button>
          <button class="reject" onclick="rejectById('${encodedId}')">Reject (discard)</button>
        </div>
      </article>
    `;
  });

  if (!cards) {
    cards = '<p class="empty">No pending submissions right now.</p>';
  }

  const html = `
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>BX Signal Admin</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #0f1115;
      --panel: #171a22;
      --line: #2a3040;
      --text: #eef3ff;
      --muted: #a9b3ca;
      --ok: #34d399;
      --bad: #f87171;
      --accent: #7dd3fc;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", system-ui, sans-serif;
      background: radial-gradient(circle at top, #151b2a, var(--bg) 55%);
      color: var(--text);
      padding: 24px 18px 40px;
    }
    .wrap {
      max-width: 980px;
      margin: 0 auto;
    }
    h1 {
      margin: 0 0 8px;
      letter-spacing: 0.02em;
    }
    .lead {
      margin: 0 0 16px;
      color: var(--muted);
      line-height: 1.45;
    }
    .stats {
      display: inline-flex;
      gap: 8px;
      margin-bottom: 16px;
      font-size: 14px;
    }
    .pill {
      border: 1px solid var(--line);
      background: rgba(125, 211, 252, 0.1);
      padding: 6px 10px;
      border-radius: 999px;
    }
    #msg {
      margin: 0 0 14px;
      min-height: 20px;
      color: var(--muted);
    }
    .card {
      border: 1px solid var(--line);
      border-radius: 14px;
      background: linear-gradient(180deg, #1a1f2c, var(--panel));
      padding: 14px;
      margin: 0 0 12px;
      box-shadow: 0 10px 26px rgba(0, 0, 0, 0.28);
    }
    .card-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      margin: 0 0 12px;
    }
    .card-head h3 {
      margin: 0;
      font-size: 18px;
      line-height: 1.25;
    }
    code {
      background: rgba(125, 211, 252, 0.12);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 4px 8px;
      font-size: 12px;
    }
    .meta {
      display: grid;
      gap: 8px;
      grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
      margin: 0 0 10px;
    }
    .meta div {
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 8px 10px;
      background: rgba(255, 255, 255, 0.02);
    }
    dt {
      color: var(--muted);
      font-size: 12px;
      margin: 0 0 3px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    dd {
      margin: 0;
      line-height: 1.4;
    }
    a { color: var(--accent); }
    .dim { color: var(--muted); }
    details {
      margin: 8px 0 10px;
    }
    summary {
      cursor: pointer;
      color: var(--muted);
    }
    pre {
      margin: 8px 0 0;
      white-space: pre-wrap;
      word-break: break-word;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 8px;
      background: #121520;
      color: #d7def5;
      font-size: 12px;
    }
    .actions {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-top: 6px;
    }
    button {
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 8px 12px;
      font-size: 13px;
      cursor: pointer;
      color: white;
      background: #2a3142;
    }
    button.approve {
      background: color-mix(in srgb, var(--ok) 32%, #1f2430);
      border-color: color-mix(in srgb, var(--ok) 45%, #2a3142);
    }
    button.reject {
      background: color-mix(in srgb, var(--bad) 24%, #1f2430);
      border-color: color-mix(in srgb, var(--bad) 40%, #2a3142);
    }
    button:disabled {
      opacity: 0.65;
      cursor: not-allowed;
    }
    .empty {
      border: 1px dashed var(--line);
      border-radius: 12px;
      padding: 14px;
      color: var(--muted);
    }
  </style>
</head>
<body>
  <main class="wrap">
    <h1>BX Signal Approval Dashboard</h1>
    <p class="lead">Each card below is one user request. Approve means it becomes visible on the public map. Reject means it is removed.</p>
    <div class="stats">
      <span class="pill">Pending: ${pending.length}</span>
      <span class="pill">Approved: ${approvedCount}</span>
    </div>
    <p id="msg" role="status" aria-live="polite"></p>
    ${cards}
  </main>
  <script>
    const msgEl = document.getElementById('msg');
    function setMsg(message, isError) {
      if (!msgEl) return;
      msgEl.textContent = message;
      msgEl.style.color = isError ? '#fda4af' : '#a9b3ca';
    }
    async function sendAction(path, id, actionWord) {
      try {
        const response = await fetch(path, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id })
        });
        const body = await response.json().catch(() => ({}));
        if (!response.ok) {
          throw new Error(body.message || 'Request failed');
        }
        setMsg(actionWord + ' complete. Reloading...', false);
        setTimeout(() => location.reload(), 300);
      } catch (err) {
        setMsg(actionWord + ' failed: ' + err.message, true);
      }
    }
    function approveById(encodedId) {
      const id = decodeURIComponent(encodedId);
      if (!confirm('Approve this request and publish it to the map?')) return;
      sendAction('/admin/approve', id, 'Approve');
    }
    function rejectById(encodedId) {
      const id = decodeURIComponent(encodedId);
      if (!confirm('Reject this request and remove it from pending?')) return;
      sendAction('/admin/reject', id, 'Reject');
    }
  </script>
</body>
</html>
  `;

  res.send(html);
});

app.get('/admin/pending', requireAdmin, (req, res) => {
  res.json(readJsonArray(PENDING_FILE));
});

// Approve a pending signal by id
app.post('/admin/approve', requireAdmin, (req, res) => {
  const { id } = req.body || {};
  if (!id || typeof id !== 'string') {
    return res.status(400).json({ success: false, message: 'Missing id' });
  }

  const pending = readJsonArray(PENDING_FILE);
  const approved = readJsonArray(APPROVED_FILE);

  const index = pending.findIndex((sig) => sig && sig.id === id);
  if (index === -1) {
    return res.status(404).json({ success: false, message: 'Pending signal not found' });
  }

  const [signal] = pending.splice(index, 1);
  approved.push({ ...signal, status: 'approved', approvedAt: new Date().toISOString() });

  const approvedSaved = writeJsonArray(APPROVED_FILE, approved);
  const pendingSaved = writeJsonArray(PENDING_FILE, pending);

  if (!approvedSaved || !pendingSaved) {
    return res.status(500).json({ success: false, message: 'Failed to save approval update' });
  }

  res.json({ success: true });
});

// Reject a pending signal by id
app.post('/admin/reject', requireAdmin, (req, res) => {
  const { id } = req.body || {};
  if (!id || typeof id !== 'string') {
    return res.status(400).json({ success: false, message: 'Missing id' });
  }

  const pending = readJsonArray(PENDING_FILE);
  const index = pending.findIndex((sig) => sig && sig.id === id);

  if (index === -1) {
    return res.status(404).json({ success: false, message: 'Pending signal not found' });
  }

  pending.splice(index, 1);

  const pendingSaved = writeJsonArray(PENDING_FILE, pending);
  if (!pendingSaved) {
    return res.status(500).json({ success: false, message: 'Failed to save rejection update' });
  }

  res.json({ success: true });
});

app.listen(port, () => {
  if (!process.env.ADMIN_PASS) {
    console.warn('ADMIN_PASS is not set. Using default password. Set ADMIN_PASS in Vercel env immediately.');
  }
  console.log(`Server running on port ${port}`);
});
