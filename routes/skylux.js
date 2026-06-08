// Unified vendor: skylux (Wiz-shape)
// OAuth2 + a SINGLE GraphQL endpoint used for BOTH directions:
//   - a `query` (issues) → PULL
//   - a `mutation` (updateIssue) → WRITEBACK
// Shared store: the issue id you query is the id you mutate.

const express = require('express');
const { getBearer, unauthorized } = require('../lib/auth');
const { issueOauthToken, hasOauthToken, recordWriteback } = require('../lib/state');
const store = require('../lib/alertStore');

const router = express.Router();

// POST /skylux/oauth2/token
router.post('/oauth2/token', (req, res) => {
  const { grant_type, client_id, client_secret } = req.body || {};
  if (grant_type !== 'client_credentials') return res.status(400).json({ error: 'unsupported grant_type' });
  if (!client_id || !client_secret) return res.status(400).json({ error: 'missing client_id/client_secret' });
  res.json({ access_token: issueOauthToken(), token_type: 'Bearer', expires_in: 3600 });
});

// POST /skylux/graphql   — PULL (query) OR WRITEBACK (mutation), routed by the operation
router.post('/graphql', (req, res) => {
  const tok = getBearer(req);
  if (!tok || !hasOauthToken(tok)) return unauthorized(res, 'call /oauth2/token first');
  const { query, variables } = req.body || {};
  if (!query) return res.status(400).json({ errors: [{ message: 'query required' }] });

  if (/mutation/i.test(query)) {
    // WRITEBACK — updateIssue
    const id = variables && variables.id;
    if (!id) return res.status(400).json({ errors: [{ message: 'variables.id required' }] });
    const patch = (variables && variables.patch) || {};
    const newStatus = patch.status || 'IN_PROGRESS';
    store.patch('skylux', 'id', id, { status: newStatus });
    recordWriteback({ vendor: 'skylux', kind: 'unified', id, patch });
    return res.json({ data: { updateIssue: { issue: { id, status: newStatus } } } });
  }

  // PULL — issues query (returns all open issues from the shared store)
  const nodes = store.all('skylux');
  res.json({ data: { issues: { nodes, pageInfo: { hasNextPage: false, endCursor: null } } } });
});

module.exports = router;
