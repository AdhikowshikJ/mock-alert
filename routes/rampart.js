// Unified vendor: rampart
// Bearer static + single pull + single close, BUT rate-limited 5/min on BOTH
// endpoints (shared limiter keyed on the token). Edge: writeback also gets
// throttled → 429 with Retry-After, so generated writeback handlers must cope
// with rate limiting, not just the pull side.

const express = require('express');
const { getBearer, unauthorized } = require('../lib/auth');
const { checkRateLimit, recordWriteback } = require('../lib/state');
const store = require('../lib/alertStore');

const router = express.Router();

function gate(req, res) {
  const tok = getBearer(req);
  if (!tok) { unauthorized(res, 'expected Authorization: Bearer <token>'); return false; }
  const rl = checkRateLimit(`rampart:${tok}`);
  if (!rl.allowed) {
    res.set('Retry-After', String(rl.retryAfter));
    res.status(429).json({ error: 'rate limit exceeded (5/min)', retry_after: rl.retryAfter });
    return false;
  }
  return true;
}

// GET /rampart/v1/detections   — PULL (single call, rate-limited)
router.get('/v1/detections', (req, res) => {
  if (!gate(req, res)) return;
  res.json({ detections: store.all('rampart') });
});

// PATCH /rampart/v1/detections/:id   — WRITEBACK (rate-limited too)
router.patch('/v1/detections/:id', (req, res) => {
  if (!gate(req, res)) return;
  const { id } = req.params;
  const status = (req.body && req.body.status) || 'resolved';
  const updated = store.patch('rampart', 'id', id, { status: 'resolved', resolution: status });
  if (!updated) return res.status(404).json({ error: 'detection not found', id });
  recordWriteback({ vendor: 'rampart', kind: 'unified', id, status });
  res.json({ updated: 1, id });
});

module.exports = router;
