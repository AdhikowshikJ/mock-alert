// Writeback archetype B — nimbusguard (escloud:nimbusguard)
// OAuth2 client_credentials → Bearer token, then single PATCH close call.
//
// Generated handlers call:
//   POST  /nimbusguard/oauth2/token   (form: grant_type=client_credentials&client_id=&client_secret=)
//   PATCH /nimbusguard/v1/findings/:id
//     Header: Authorization: Bearer <access_token>
//     Body:   { "state": "<state>", "classification": "<classification>", "determination": "<determination>" }

const express = require('express');
const { getBearer, unauthorized } = require('../lib/auth');
const { issueOauthToken, hasOauthToken, recordWriteback } = require('../lib/state');

const router = express.Router();

// POST /nimbusguard/oauth2/token
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

// PATCH /nimbusguard/v1/findings/:id
router.patch('/v1/findings/:id', (req, res) => {
  const token = getBearer(req);
  if (!token) return unauthorized(res, 'missing Bearer token (call /oauth2/token first)');
  if (!hasOauthToken(token)) return unauthorized(res, 'token not issued by /oauth2/token');

  const { id } = req.params;
  const { state, classification, determination } = req.body || {};
  if (!state) return res.status(400).json({ error: 'state required' });

  recordWriteback({ vendor: 'nimbusguard', archetype: 'B', id, state, classification, determination });
  res.json({ id, state, classification, determination });
});

module.exports = router;
