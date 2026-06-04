// Brief 5 — list_then_split (aegis)
// Paginated list of alert IDs, then per-id detail fetch.

const express = require('express');
const { getApiKey, unauthorized } = require('../lib/auth');
const { aegisAlertIds, aegisAlertDetail } = require('../lib/fixtures');

const router = express.Router();
const PAGE_SIZE = 5;

// GET /aegis/v2/alerts?since=<iso>&limit=<n>&cursor=<c>
// Returns only IDs (no detail).
router.get('/v2/alerts', (req, res) => {
  const token = getApiKey(req);
  if (!token) return unauthorized(res, 'expected X-Api-Key header');

  let pageIdx = 0;
  if (req.query.cursor) {
    const m = String(req.query.cursor).match(/^p(\d+)$/);
    if (!m) return res.status(400).json({ error: 'invalid cursor format', expected: 'p<N>' });
    pageIdx = parseInt(m[1], 10);
  }
  const start = pageIdx * PAGE_SIZE;
  const slice = aegisAlertIds.slice(start, start + PAGE_SIZE).map(id => ({ id }));
  const hasMore = (start + PAGE_SIZE) < aegisAlertIds.length;
  const next_cursor = hasMore ? `p${pageIdx + 1}` : null;

  res.json({ alerts: slice, next_cursor });
});

// GET /aegis/v2/alerts/:id
router.get('/v2/alerts/:id', (req, res) => {
  const token = getApiKey(req);
  if (!token) return unauthorized(res, 'expected X-Api-Key header');
  if (!aegisAlertIds.includes(req.params.id)) {
    return res.status(404).json({ error: 'alert not found', id: req.params.id });
  }
  res.json(aegisAlertDetail(req.params.id));
});

module.exports = router;
