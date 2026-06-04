// Brief 1 — vanilla_bearer
// Static Bearer + single GET + no pagination.

const express = require('express');
const { getBearer, unauthorized } = require('../lib/auth');
const { vanillaBearerAlerts } = require('../lib/fixtures');

const router = express.Router();

// GET /vanilla-bearer/v1/alerts?since=<iso>
router.get('/v1/alerts', (req, res) => {
  const token = getBearer(req);
  if (!token) return unauthorized(res, 'expected Authorization: Bearer <token>');
  res.json({ alerts: vanillaBearerAlerts });
});

module.exports = router;
