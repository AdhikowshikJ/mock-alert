// Brief 7 — rate_limit_retry (pulse)
// Returns 429 with Retry-After when over 5/min. Tests that generated
// retry.condition correctly retries on 429.

const express = require('express');
const { getApiKey, unauthorized } = require('../lib/auth');
const { checkRateLimit } = require('../lib/state');
const { pulseDetections } = require('../lib/fixtures');

const router = express.Router();

// GET /pulse/v1/detections?since=<iso>
router.get('/v1/detections', (req, res) => {
  const token = getApiKey(req);
  if (!token) return unauthorized(res, 'expected X-Api-Key header');

  const result = checkRateLimit(token);
  if (!result.allowed) {
    res.set('Retry-After', String(result.retryAfter));
    return res.status(429).json({
      error: 'rate_limit_exceeded',
      retry_after_seconds: result.retryAfter
    });
  }
  res.json({ detections: pulseDetections });
});

module.exports = router;
