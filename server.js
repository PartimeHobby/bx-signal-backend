const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

const DATA_DIR = process.env.VERCEL ? '/tmp' : __dirname;
const APPROVED_FILE = path.join(DATA_DIR, 'approved.json');
const PENDING_FILE = path.join(DATA_DIR, 'pending.json');

app.use(express.json());

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
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

let approved = readJsonArray(APPROVED_FILE); // Live signals
let pending = readJsonArray(PENDING_FILE); // Waiting for approval

// Get approved signals (for the map)
app.get('/api/signals', (req, res) => {
  approved = readJsonArray(APPROVED_FILE);
  res.json(approved);
});

// Add new signal to pending
app.post('/api/signals', (req, res) => {
  const newSignal = req.body;
  if (!newSignal || typeof newSignal !== 'object') {
    return res.status(400).json({ success: false, message: 'Invalid payload' });
  }

  newSignal.id = `sig-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;
  pending.push(newSignal);

  const saved = writeJsonArray(PENDING_FILE, pending);
  if (!saved) {
    return res.status(500).json({ success: false, message: 'Could not save pending signal' });
  }

  res.status(201).json({ success: true, message: 'Signal submitted for review!' });
});

// Admin page to review pending
app.get('/admin', (req, res) => {
  pending = readJsonArray(PENDING_FILE);

  let html = '<h1>Admin Approval Dashboard</h1><ul>';
  pending.forEach((sig, index) => {
    const safeTitle = escapeHtml(sig.title || 'Untitled');
    const safeStart = escapeHtml(sig.startTime || 'No time');
    html += `<li>${safeTitle} (${safeStart}) <button onclick="approve(${index})">Approve</button> <button onclick="reject(${index})">Reject</button></li>`;
  });
  html += '</ul>';
  html += `
    <script>
      function approve(index) {
        fetch('/admin/approve', { method: 'POST', body: JSON.stringify({ index }), headers: {'Content-Type': 'application/json'} })
          .then(() => location.reload());
      }
      function reject(index) {
        fetch('/admin/reject', { method: 'POST', body: JSON.stringify({ index }), headers: {'Content-Type': 'application/json'} })
          .then(() => location.reload());
      }
    </script>
  `;
  res.send(html);
});

// Approve a pending signal
app.post('/admin/approve', (req, res) => {
  const { index } = req.body;
  if (index >= 0 && index < pending.length) {
    approved.push(pending.splice(index, 1)[0]);

    const approvedSaved = writeJsonArray(APPROVED_FILE, approved);
    const pendingSaved = writeJsonArray(PENDING_FILE, pending);
    if (!approvedSaved || !pendingSaved) {
      return res.status(500).json({ success: false, message: 'Failed to save approval update' });
    }
  }
  res.json({ success: true });
});

// Reject a pending signal
app.post('/admin/reject', (req, res) => {
  const { index } = req.body;
  if (index >= 0 && index < pending.length) {
    pending.splice(index, 1);

    const pendingSaved = writeJsonArray(PENDING_FILE, pending);
    if (!pendingSaved) {
      return res.status(500).json({ success: false, message: 'Failed to save rejection update' });
    }
  }
  res.json({ success: true });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
