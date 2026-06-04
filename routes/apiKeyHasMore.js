// Brief 2 — api_key_has_more (cobalt)
// Literal `Authorization: ApiToken <tok>` + boolean has_more pagination.

const express = require('express');
const { getApiToken, unauthorized } = require('../lib/auth');
const { cobaltDetections } = require('../lib/fixtures');

const router = express.Router();
const PAGE_SIZE = 10;

// GET /cobalt/api/v2/detections?from=<iso>&limit=<n>&offset=<n>
router.get('/api/v2/detections', (req, res) => {
  const token = getApiToken(req);
  if (!token) return unauthorized(res, 'expected Authorization: ApiToken <token> (literal — NOT Bearer)');

  const offset = parseInt(req.query.offset, 10) || 0;
  const limit  = Math.min(parseInt(req.query.limit, 10) || PAGE_SIZE, 200);

  const slice = cobaltDetections.slice(offset, offset + limit);
  const has_more = (offset + limit) < cobaltDetections.length;

  res.json({
    data: slice,
    page: {
      has_more,
      next_offset: has_more ? offset + limit : null
    }
  });
});

module.exports = router;
