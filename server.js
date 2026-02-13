const express = require('express');
const fs = require('fs');
const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

let signals = []; // Start with empty list

// Load signals from file if exists
if (fs.existsSync('signals.json')) {
  signals = JSON.parse(fs.readFileSync('signals.json', 'utf8'));
}

// Get all signals
app.get('/api/signals', (req, res) => {
  res.json(signals);
});

// Add new signal
app.post('/api/signals', (req, res) => {
  const newSignal = req.body;
  newSignal.id = 'sig-' + (signals.length + 1); // Simple ID
  signals.push(newSignal);
  fs.writeFileSync('signals.json', JSON.stringify(signals)); // Save to file
  res.json({ success: true, message: 'Signal added!' });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
