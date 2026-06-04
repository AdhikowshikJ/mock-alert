// Brief 3 — oauth2_cursor (vortex)
// OAuth2 client_credentials grant + cursor pagination.

const express = require('express');
const { getBearer, unauthorized } = require('../lib/auth');
const { issueOauthToken, hasOauthToken } = require('../lib/state');
const { vortexThreats } = require('../lib/fixtures');

const router = express.Router();
const PAGE_SIZE = 10;

// POST /vortex/oauth/token
// Form body: grant_type=client_credentials&client_id=...&client_secret=...
router.post('/oauth/token', (req, res) => {
  const { grant_type, client_id, client_secret } = req.body || {};
  if (grant_type !== 'client_credentials') {
    return res.status(400).json({ error: 'unsupported grant_type', expected: 'client_credentials' });
  }
  if (!client_id || !client_secret) {
    return res.status(400).json({ error: 'missing client_id or client_secret in form body' });
  }
  // Mock: any non-empty client_id/secret pair gets a token.
  const access_token = issueOauthToken();
  res.json({ access_token, token_type: 'Bearer', expires_in: 3600 });
});

// GET /vortex/v3/threats?since=<iso>&cursor=<c>&page_size=<n>
router.get('/v3/threats', (req, res) => {
  const token = getBearer(req);
  if (!token) return unauthorized(res, 'missing Bearer token (call /oauth/token first)');
  if (!hasOauthToken(token)) return unauthorized(res, 'token not issued by /oauth/token');

  let pageIdx = 0;
  if (req.query.cursor) {
    const m = String(req.query.cursor).match(/^page(\d+)$/);
    if (!m) return res.status(400).json({ error: 'invalid cursor format', expected: 'page<N>' });
    pageIdx = parseInt(m[1], 10) - 1;
    if (pageIdx < 0) return res.status(400).json({ error: 'cursor page index must be >= 1' });
  }

  const start = pageIdx * PAGE_SIZE;
  const slice = vortexThreats.slice(start, start + PAGE_SIZE);
  const hasMore = (start + PAGE_SIZE) < vortexThreats.length;
  const next_cursor = hasMore ? `page${pageIdx + 2}` : null;

  res.json({
    threats: slice,
    pagination: next_cursor ? { next_cursor } : { next_cursor: null }
  });
});

module.exports = router;
