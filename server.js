const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// ---------------------------------------------------------------
// In-memory "incident" store (mock data matching the demo dashboard)
// ---------------------------------------------------------------
const incidents = {
  4471: {
    id: 4471,
    customer: 'Arjun Menon',
    status: 'open',
    attackChain: [
      { step: 'Login', detail: 'Customer authenticates successfully' },
      { step: 'New Device', detail: 'Device fingerprint never seen before' },
      { step: 'VPN Detected', detail: 'Origin IP masked via VPN exit node' },
      { step: 'OTP Failed', detail: '2 failed one-time-password attempts' },
      { step: '₹7.5 Lakh Transfer', detail: "150x the customer's average transaction" },
      { step: 'Firewall Alert', detail: 'Destination account flagged in threat feed' }
    ],
    signals: {
      newDevice: true,
      vpn: true,
      otpFailures: 2,
      amount: 750000,
      avgAmount: 8000,
      locationMismatch: true,
      oddHour: true,
      firewallAlert: true
    },
    twin: {
      baseline: { location: 'Coimbatore', loginTime: '09:00', device: 'Android', avgTransfer: 8000 },
      today: { location: 'Delhi', loginTime: '02:00', device: 'Windows', avgTransfer: 750000 }
    },
    log: []
  }
};

// ---------------------------------------------------------------
// 1. RISK SCORING ENGINE (weighted rule model, capped at 100)
// ---------------------------------------------------------------
function computeRisk(signals) {
  const breakdown = [];
  let score = 0;

  const add = (points, label) => {
    score += points;
    breakdown.push({ label, points });
  };

  if (signals.newDevice) add(18, 'Unrecognized device');
  if (signals.vpn) add(15, 'VPN / IP masking detected');
  if (signals.otpFailures) add(Math.min(20, signals.otpFailures * 10), `${signals.otpFailures} failed OTP attempt(s)`);
  if (signals.locationMismatch) add(15, 'Login location deviates from baseline');
  if (signals.oddHour) add(10, 'Login at unusual hour');
  if (signals.firewallAlert) add(12, 'Destination flagged by firewall/threat feed');

  if (signals.amount && signals.avgAmount) {
    const ratio = signals.amount / signals.avgAmount;
    const amtPoints = Math.min(30, Math.round(Math.log2(ratio + 1) * 6));
    if (ratio > 1.5) add(amtPoints, `Transaction ${ratio.toFixed(0)}x above average`);
  }

  score = Math.min(100, score);

  let action;
  if (score >= 85) action = 'Freeze account & escalate to SOC';
  else if (score >= 65) action = 'Require manager approval';
  else if (score >= 40) action = 'Require face verification';
  else if (score >= 15) action = 'Require OTP step-up';
  else action = 'Allow — no additional friction';

  return { score, breakdown, action };
}

app.post('/api/score', (req, res) => {
  const signals = req.body || {};
  res.json(computeRisk(signals));
});

// ---------------------------------------------------------------
// 2. CORRELATION ENGINE — returns the attack graph for an incident
// ---------------------------------------------------------------
app.get('/api/incident/:id', (req, res) => {
  const inc = incidents[req.params.id];
  if (!inc) return res.status(404).json({ error: 'Incident not found' });

  const risk = computeRisk(inc.signals);
  const twinMatch = computeMatch(inc.twin.baseline, inc.twin.today);

  res.json({
    id: inc.id,
    customer: inc.customer,
    status: inc.status,
    attackChain: inc.attackChain,
    rawAlertCount: 312,
    correlatedIncidentCount: 1,
    risk,
    twin: {
      baseline: inc.twin.baseline,
      today: inc.twin.today,
      ...twinMatch
    },
    log: inc.log
  });
});

app.post('/api/incident/:id/action', (req, res) => {
  const inc = incidents[req.params.id];
  if (!inc) return res.status(404).json({ error: 'Incident not found' });

  const { action = 'block' } = req.body || {};
  const actionKey = String(action).toLowerCase();
  const statusMap = {
    block: 'blocked',
    escalate: 'escalated',
    resolve: 'resolved',
    reset: 'open'
  };

  const nextStatus = statusMap[actionKey] || 'open';
  inc.status = nextStatus;
  inc.log.push({
    ts: new Date().toISOString(),
    action: actionKey,
    status: nextStatus,
    note: `${actionKey} action applied to incident ${inc.id}`
  });

  res.json({ id: inc.id, status: inc.status, action: actionKey, log: inc.log });
});

app.get('/api/incident/:id/log', (req, res) => {
  const inc = incidents[req.params.id];
  if (!inc) return res.status(404).json({ error: 'Incident not found' });
  res.json({ id: inc.id, log: inc.log });
});

// ---------------------------------------------------------------
// 3. DIGITAL TWIN — behaviour match %
// ---------------------------------------------------------------
function computeMatch(baseline, today) {
  const fields = Object.keys(baseline);
  let deviatedWeight = 0;
  const weights = { location: 25, loginTime: 20, device: 20, avgTransfer: 35 };
  const deviations = [];

  fields.forEach((field) => {
    const b = baseline[field];
    const t = today[field];
    let deviated = false;

    if (field === 'avgTransfer') {
      deviated = t / b > 3;
    } else {
      deviated = String(b).toLowerCase() !== String(t).toLowerCase();
    }

    if (deviated) {
      deviatedWeight += weights[field] || 10;
      deviations.push(field);
    }
  });

  const match = Math.max(0, 100 - deviatedWeight);
  return { matchPercent: match, deviatedBy: 100 - match, deviations };
}

app.post('/api/twin', (req, res) => {
  const { baseline, today } = req.body || {};
  if (!baseline || !today) return res.status(400).json({ error: 'baseline and today required' });
  res.json(computeMatch(baseline, today));
});

app.get('/api/twin/:incidentId', (req, res) => {
  const inc = incidents[req.params.incidentId];
  if (!inc) return res.status(404).json({ error: 'Incident not found' });
  res.json(computeMatch(inc.twin.baseline, inc.twin.today));
});

// ---------------------------------------------------------------
// 4. ADAPTIVE SECURITY ENGINE — risk score -> response tier
// ---------------------------------------------------------------
const tiers = [
  { min: 0, max: 14, action: 'Allow', friction: 'None' },
  { min: 15, max: 39, action: 'Ask for OTP', friction: 'Low' },
  { min: 40, max: 64, action: 'Face verification', friction: 'Medium' },
  { min: 65, max: 84, action: 'Manager approval', friction: 'High' },
  { min: 85, max: 100, action: 'Freeze account', friction: 'Maximum' }
];

app.post('/api/adaptive', (req, res) => {
  const score = Number((req.body || {}).score);
  if (Number.isNaN(score) || score < 0 || score > 100) return res.status(400).json({ error: 'score must be 0-100' });

  const tier = tiers.find((entry) => score >= entry.min && score <= entry.max);
  res.json({ score, tier });
});

// ---------------------------------------------------------------
// 5. THREAT INVESTIGATION COPILOT — rule-based Q&A grounded in incident data
// ---------------------------------------------------------------
app.post('/api/copilot', (req, res) => {
  const { question = '', incidentId = 4471 } = req.body || {};
  const inc = incidents[incidentId];
  const q = question.toLowerCase();
  let answer;

  if (!inc) {
    answer = "I don't have data on that incident.";
  } else if (q.includes('why') && q.includes('risk')) {
    answer = 'The customer has never logged in from this device. The transaction is 90x higher than their average, and it followed multiple failed login attempts.';
  } else if (q.includes('what should i do') || q.includes('recommend')) {
    answer = 'Temporarily hold the transaction and require biometric verification before approval.';
  } else if (q.includes('confiden')) {
    answer = 'High confidence — four independent signals (device, VPN, OTP failures, amount) all deviate from baseline simultaneously, which is rare in legitimate sessions.';
  } else if (q.includes('device')) {
    answer = 'This session used a device fingerprint never previously associated with this account.';
  } else if (q.includes('location') || q.includes('where')) {
    answer = `Baseline location is ${inc.twin.baseline.location}; today's session originated from ${inc.twin.today.location}.`;
  } else if (q.includes('amount') || q.includes('transfer') || q.includes('money')) {
    const ratio = Math.round(inc.signals.amount / inc.signals.avgAmount);
    answer = `The transfer was ₹${inc.signals.amount.toLocaleString('en-IN')}, roughly ${ratio}x the customer's average of ₹${inc.signals.avgAmount.toLocaleString('en-IN')}.`;
  } else {
    answer = 'Based on correlated signals — new device, VPN usage, OTP failures, and an anomalous transfer amount — this incident matches an account-takeover pattern.';
  }

  res.json({ question, answer });
});

app.get('/api/health', (req, res) => res.json({ status: 'ok', service: 'quantumshield-api' }));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 4000;

if (require.main === module) {
  app.listen(PORT, () => console.log(`QuantumShield API running on http://localhost:${PORT}`));
}

module.exports = { app, incidents, computeRisk, computeMatch };
