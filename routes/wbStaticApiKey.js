// Writeback archetype A — sentinelshield (esendpoint:sentinelshield)
// Static API key (X-Api-Key) + single close call. No token round-trip.
//
// Generated handler calls:
//   PATCH /sentinelshield/api/v2/detections/resolve
//   Header: x-api-key: <api_key>
//   Body:   { "detection_ids": ["<id>"], "resolution": "<resolution>", "note": "..." }

const express = require('express');
const { getApiKey, unauthorized } = require('../lib/auth');
const { recordWriteback } = require('../lib/state');

const router = express.Router();

const VALID_RESOLUTIONS = ['confirmed_threat', 'benign', 'undetermined'];

// PATCH /sentinelshield/api/v2/detections/resolve
router.patch('/api/v2/detections/resolve', (req, res) => {
  const key = getApiKey(req);
  if (!key) return unauthorized(res, 'expected X-Api-Key: <api_key>');

  const { detection_ids, resolution, note } = req.body || {};
  if (!Array.isArray(detection_ids) || detection_ids.length === 0) {
    return res.status(400).json({ error: 'detection_ids[] required' });
  }
  if (!VALID_RESOLUTIONS.includes(resolution)) {
    return res.status(400).json({ error: 'invalid resolution', expected: VALID_RESOLUTIONS, got: resolution });
  }

  recordWriteback({ vendor: 'sentinelshield', archetype: 'A', detection_ids, resolution, note });
  res.json({ updated: detection_ids.length, failed: 0, resolution });
});

module.exports = router;
