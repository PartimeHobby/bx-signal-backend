const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

const SIGNALS_FILE = process.env.VERCEL
  ? path.join('/tmp', 'signals.json')
  : path.join(__dirname, 'signals.json');

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

function readSignalsFromFile() {
  try {
    if (!fs.existsSync(SIGNALS_FILE)) return [];
    const raw = fs.readFileSync(SIGNALS_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    console.error('Failed to read signals file:', err.message);
    return [];
  }
}

function writeSignalsToFile(nextSignals) {
  try {
    fs.writeFileSync(SIGNALS_FILE, JSON.stringify(nextSignals, null, 2), 'utf8');
    return true;
  } catch (err) {
    console.error('Failed to write signals file:', err.message);
    return false;
  }
}

let signals = readSignalsFromFile();

app.get('/api/signals', (req, res) => {
  const latestFromDisk = readSignalsFromFile();
  if (latestFromDisk.length || !signals.length) {
    signals = latestFromDisk;
  }
  res.json(signals);
});

app.post('/api/signals', (req, res) => {
  const incoming = req.body;
  if (!incoming || typeof incoming !== 'object') {
    return res.status(400).json({ success: false, message: 'Invalid payload' });
  }

  const newSignal = {
    ...incoming,
    id: incoming.id || `sig-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`
  };

  signals.push(newSignal);
  const persisted = writeSignalsToFile(signals);

  res.status(201).json({
    success: true,
    message: persisted ? 'Signal added!' : 'Signal added in memory only.',
    persisted,
    signal: newSignal
  });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
