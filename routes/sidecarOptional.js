// Brief 8 — sidecar_optional (helix)
// Cursor-paginated alerts (primary). Per-id asset enrichment is flaky:
// asset_ids ending in '00' return 404, testing continue-on-error semantics.

const express = require('express');
const { getBearer, unauthorized } = require('../lib/auth');
const { helixAlerts } = require('../lib/fixtures');

const router = express.Router();
const PAGE_SIZE = 5;

// GET /helix/api/v1/alerts?since=<iso>&cursor=<n>
router.get('/api/v1/alerts', (req, res) => {
  const token = getBearer(req);
  if (!token) return unauthorized(res, 'expected Authorization: Bearer <token>');

  let pageIdx = 0;
  if (req.query.cursor) {
    pageIdx = parseInt(req.query.cursor, 10);
    if (isNaN(pageIdx) || pageIdx < 0) {
      return res.status(400).json({ error: 'invalid cursor (expected non-negative integer)' });
    }
  }
  const start = pageIdx * PAGE_SIZE;
  const slice = helixAlerts.slice(start, start + PAGE_SIZE);
  const hasMore = (start + PAGE_SIZE) < helixAlerts.length;
  const nextCursor = hasMore ? String(pageIdx + 1) : null;

  res.json({ alerts: slice, nextCursor });
});

// GET /helix/api/v1/assets/:id
// Deterministic flakiness: asset_ids ending in '00' return 404, others 200.
router.get('/api/v1/assets/:id', (req, res) => {
  const token = getBearer(req);
  if (!token) return unauthorized(res, 'expected Authorization: Bearer <token>');

  if (req.params.id.endsWith('00')) {
    return res.status(404).json({ error: 'asset not found', asset_id: req.params.id });
  }
  res.json({
    asset_id: req.params.id,
    owner: 'team-platform',
    criticality: ['low', 'medium', 'high'][req.params.id.length % 3]
  });
});

module.exports = router;
