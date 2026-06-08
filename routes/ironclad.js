// Unified vendor: ironclad
// X-Api-Key + has_more pull + single close by id.
// Failure edges: close an UNKNOWN id → 404; re-close an already-closed id → 200 no-op.

const express = require('express');
const { getApiKey, unauthorized } = require('../lib/auth');
const { recordWriteback } = require('../lib/state');
const store = require('../lib/alertStore');

const router = express.Router();
const PAGE = 5;

// GET /ironclad/v2/detections?offset=0&limit=5   — PULL (has_more boolean pagination)
router.get('/v2/detections', (req, res) => {
  if (!getApiKey(req)) return unauthorized(res, 'expected X-Api-Key: <api_key>');
  const offset = parseInt(req.query.offset) || 0;
  const limit = Math.min(parseInt(req.query.limit) || PAGE, 100);
  const { items, next, total } = store.page('ironclad', offset, limit);
  res.json({ detections: items, has_more: next !== null, total });
});

// PATCH /ironclad/v2/detections/:id   — WRITEBACK (close by id; 404 / idempotent edges)
router.patch('/v2/detections/:id', (req, res) => {
  if (!getApiKey(req)) return unauthorized(res, 'expected X-Api-Key: <api_key>');
  const { id } = req.params;
  const existing = store.find('ironclad', 'id', id);
  if (!existing) return res.status(404).json({ error: 'detection not found', id });        // edge: unknown id
  if (existing.status === 'closed') {                                                        // edge: idempotent re-close
    return res.json({ updated: 0, already_closed: true, id });
  }
  const status = (req.body && req.body.status) || 'closed';
  store.patch('ironclad', 'id', id, { status: 'closed', resolution: status });
  recordWriteback({ vendor: 'ironclad', kind: 'unified', id, status });
  res.json({ updated: 1, id });
});

module.exports = router;
