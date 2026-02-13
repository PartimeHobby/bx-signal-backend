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

  let html = '<h1>Admin Approval Dashboard</h1>';
  html += `<p>Pending: ${pending.length} | Approved: ${approvedCount}</p>`;
  html += '<ul>';

  pending.forEach((sig) => {
    const safeId = String(sig.id || '');
    const safeTitle = escapeHtml(sig.title || 'Untitled');
    const safeStart = escapeHtml(sig.startTime || 'No time');
    const encodedId = encodeURIComponent(safeId);
    html += `<li><strong>${safeTitle}</strong> (${safeStart}) [${escapeHtml(safeId)}] <button onclick="approveById('${encodedId}')">Approve</button> <button onclick="rejectById('${encodedId}')">Reject</button></li>`;
  });

  html += '</ul>';
  html += `
    <script>
      function approveById(encodedId) {
        const id = decodeURIComponent(encodedId);
        fetch('/admin/approve', {
          method: 'POST',
          body: JSON.stringify({ id }),
          headers: { 'Content-Type': 'application/json' }
        }).then(() => location.reload());
      }
      function rejectById(encodedId) {
        const id = decodeURIComponent(encodedId);
        fetch('/admin/reject', {
          method: 'POST',
          body: JSON.stringify({ id }),
          headers: { 'Content-Type': 'application/json' }
        }).then(() => location.reload());
      }
    </script>
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
