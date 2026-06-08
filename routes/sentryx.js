// Unified vendor: sentryx (SentinelOne-shape)
// ApiToken (one token for BOTH) + offset pull + multi-step writeback (resolve + add note).
// Shared store: threat_id pulled = threat_id resolved.

const express = require('express');
const { getApiToken, unauthorized } = require('../lib/auth');
const { recordWriteback } = require('../lib/state');
const store = require('../lib/alertStore');

const router = express.Router();
const LIMIT = 6;

// GET /sentryx/threats?skip=0&limit=6   — PULL (offset pagination)
router.get('/threats', (req, res) => {
  if (!getApiToken(req)) return unauthorized(res, 'expected Authorization: ApiToken <token>');
  const skip = parseInt(req.query.skip) || 0;
  const limit = Math.min(parseInt(req.query.limit) || LIMIT, 100);
  const { items, next, total } = store.page('sentryx', skip, limit);
  res.json({ data: items, pagination: { totalItems: total, nextSkip: next } });
});

// POST /sentryx/threats/resolve   — WRITEBACK step 1 (close incident)
router.post('/threats/resolve', (req, res) => {
  if (!getApiToken(req)) return unauthorized(res, 'expected Authorization: ApiToken <token>');
  const data = (req.body && req.body.data) || {};
  const filter = (req.body && req.body.filter) || {};
  if (!data.incidentStatus || !data.analystVerdict) return res.status(400).json({ error: 'data.incidentStatus + analystVerdict required' });
  if (!Array.isArray(filter.ids) || filter.ids.length === 0) return res.status(400).json({ error: 'filter.ids[] required' });
  let affected = 0;
  filter.ids.forEach(id => {
    if (store.patch('sentryx', 'threat_id', id, { status: data.incidentStatus, analystVerdict: data.analystVerdict })) affected += 1;
  });
  recordWriteback({ vendor: 'sentryx', kind: 'unified', step: 'resolve', incidentStatus: data.incidentStatus, analystVerdict: data.analystVerdict, accountIds: filter.accountIds, ids: filter.ids, affected });
  res.json({ data: { affected } });
});

// POST /sentryx/threats/:id/notes   — WRITEBACK step 2 (add note, best-effort)
router.post('/threats/:id/notes', (req, res) => {
  if (!getApiToken(req)) return unauthorized(res, 'expected Authorization: ApiToken <token>');
  const text = req.body && req.body.data && req.body.data.text;
  if (!text) return res.status(400).json({ error: 'data.text required' });
  recordWriteback({ vendor: 'sentryx', kind: 'unified', step: 'note', id: req.params.id, text });
  res.json({ data: { id: `note-${Date.now()}`, threat_id: req.params.id } });
});

module.exports = router;
