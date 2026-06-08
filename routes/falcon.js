// Unified vendor: falcon (CrowdStrike-shape)
// OAuth2 client_credentials (one token for BOTH) + cursor pull + single-call close.
// Pull and writeback share the same alert store → the composite_id you pull is the
// id you close, and a re-pull shows status flipped to "closed".

const express = require('express');
const { getBearer, unauthorized } = require('../lib/auth');
const { issueOauthToken, hasOauthToken, recordWriteback } = require('../lib/state');
const store = require('../lib/alertStore');

const router = express.Router();
const PAGE = 5;

// POST /falcon/oauth2/token  (shared by pull + writeback)
router.post('/oauth2/token', (req, res) => {
  const { grant_type, client_id, client_secret } = req.body || {};
  if (grant_type !== 'client_credentials') return res.status(400).json({ error: 'unsupported grant_type' });
  if (!client_id || !client_secret) return res.status(400).json({ error: 'missing client_id/client_secret' });
  res.json({ access_token: issueOauthToken(), token_type: 'Bearer', expires_in: 3600 });
});

// GET /falcon/alerts?cursor=pageN   — PULL (cursor pagination)
router.get('/alerts', (req, res) => {
  const tok = getBearer(req);
  if (!tok || !hasOauthToken(tok)) return unauthorized(res, 'call /oauth2/token first');
  let pageIdx = 0;
  if (req.query.cursor) {
    const m = String(req.query.cursor).match(/^page(\d+)$/);
    if (!m) return res.status(400).json({ error: 'invalid cursor', expected: 'page<N>' });
    pageIdx = parseInt(m[1], 10) - 1;
  }
  const { items, next } = store.page('falcon', pageIdx * PAGE, PAGE);
  res.json({ alerts: items, pagination: { next_cursor: next !== null ? `page${pageIdx + 2}` : null } });
});

// PATCH /falcon/alerts   — WRITEBACK (single call, close by composite_id)
router.patch('/alerts', (req, res) => {
  const tok = getBearer(req);
  if (!tok || !hasOauthToken(tok)) return unauthorized(res, 'call /oauth2/token first');
  const { composite_ids, action } = req.body || {};
  if (!Array.isArray(composite_ids) || composite_ids.length === 0) {
    return res.status(400).json({ error: 'composite_ids[] required' });
  }
  let updated = 0;
  composite_ids.forEach(id => {
    if (store.patch('falcon', 'composite_id', id, { status: 'closed', resolution: action || 'resolved' })) updated += 1;
  });
  recordWriteback({ vendor: 'falcon', kind: 'unified', composite_ids, action: action || 'resolved', updated });
  res.json({ updated, failed: composite_ids.length - updated });
});

module.exports = router;
