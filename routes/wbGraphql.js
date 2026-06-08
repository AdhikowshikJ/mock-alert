// Writeback archetype D — lumen (escloud:lumen)
// OAuth2 client_credentials → Bearer token, then a single GraphQL mutation.
//
// Generated handlers call:
//   POST /lumen/oauth2/token   (form: grant_type=client_credentials&client_id=&client_secret=)
//   POST /lumen/graphql
//     Header: Authorization: Bearer <access_token>
//     Body:   { "query": "mutation UpdateIssue(...) {...}", "variables": { "id": "...", "patch": {...} } }

const express = require('express');
const { getBearer, unauthorized } = require('../lib/auth');
const { issueOauthToken, hasOauthToken, recordWriteback } = require('../lib/state');

const router = express.Router();

// POST /lumen/oauth2/token
router.post('/oauth2/token', (req, res) => {
  const { grant_type, client_id, client_secret } = req.body || {};
  if (grant_type !== 'client_credentials') {
    return res.status(400).json({ error: 'unsupported grant_type', expected: 'client_credentials' });
  }
  if (!client_id || !client_secret) {
    return res.status(400).json({ error: 'missing client_id or client_secret in form body' });
  }
  const access_token = issueOauthToken();
  res.json({ access_token, token_type: 'Bearer', expires_in: 3600 });
});

// POST /lumen/graphql
router.post('/graphql', (req, res) => {
  const token = getBearer(req);
  if (!token) return unauthorized(res, 'missing Bearer token (call /oauth2/token first)');
  if (!hasOauthToken(token)) return unauthorized(res, 'token not issued by /oauth2/token');

  const { query, variables } = req.body || {};
  if (!query || !/mutation/i.test(query)) {
    return res.status(400).json({ errors: [{ message: 'expected a GraphQL mutation in "query"' }] });
  }
  const id = (variables && variables.id) || null;
  if (!id) {
    return res.status(400).json({ errors: [{ message: 'variables.id required' }] });
  }
  const patch = (variables && variables.patch) || {};
  const newStatus = patch.status || 'IN_PROGRESS';

  recordWriteback({ vendor: 'lumen', archetype: 'D', id, patch });
  res.json({ data: { updateIssue: { issue: { id, status: newStatus } } } });
});

module.exports = router;
