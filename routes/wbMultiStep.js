// Writeback archetype C — threatnexus (esendpoint:threatnexus)
// Static ApiToken scheme + MULTI-STEP: close incident, then add a note.
//
// Generated handlers call:
//   POST /threatnexus/web/api/v2.1/incidents/resolve
//     Header: Authorization: ApiToken <api_token>
//     Body:   { "data": { "incidentStatus": "<status>", "analystVerdict": "<verdict>" },
//               "filter": { "accountIds": ["<account_id>"], "ids": ["<id>"] } }
//   POST /threatnexus/web/api/v2.1/incidents/:id/notes
//     Header: Authorization: ApiToken <api_token>
//     Body:   { "data": { "text": "..." } }

const express = require('express');
const { getApiToken, unauthorized } = require('../lib/auth');
const { recordWriteback } = require('../lib/state');

const router = express.Router();

// POST /threatnexus/web/api/v2.1/incidents/resolve
router.post('/web/api/v2.1/incidents/resolve', (req, res) => {
  const token = getApiToken(req);
  if (!token) return unauthorized(res, 'expected Authorization: ApiToken <token>');

  const data = (req.body && req.body.data) || {};
  const filter = (req.body && req.body.filter) || {};
  if (!data.incidentStatus || !data.analystVerdict) {
    return res.status(400).json({ error: 'data.incidentStatus and data.analystVerdict required' });
  }
  if (!Array.isArray(filter.ids) || filter.ids.length === 0) {
    return res.status(400).json({ error: 'filter.ids[] required' });
  }

  recordWriteback({
    vendor: 'threatnexus', archetype: 'C', step: 'close',
    incidentStatus: data.incidentStatus, analystVerdict: data.analystVerdict,
    accountIds: filter.accountIds, ids: filter.ids
  });
  res.json({ data: { affected: filter.ids.length } });
});

// POST /threatnexus/web/api/v2.1/incidents/:id/notes
router.post('/web/api/v2.1/incidents/:id/notes', (req, res) => {
  const token = getApiToken(req);
  if (!token) return unauthorized(res, 'expected Authorization: ApiToken <token>');

  const { id } = req.params;
  const text = req.body && req.body.data && req.body.data.text;
  if (!text) return res.status(400).json({ error: 'data.text required' });

  recordWriteback({ vendor: 'threatnexus', archetype: 'C', step: 'note', id, text });
  res.json({ data: { id: `note-${Date.now()}`, incident_id: id } });
});

module.exports = router;
