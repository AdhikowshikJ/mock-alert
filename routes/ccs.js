// CCS v4 mock — returns canned secret blobs per integration name.
//
// In production, Atlas hits a real CCS v4 service. This mock is here for
// (a) documenting the expected secret shape per vendor, and
// (b) local execution scenarios where we replace the CCS endpoint.
//
// The wrapper shape matches what http_get_sensor_secret_v4 returns:
//   { data: { <INTEGRATION_NAME>: { ...fields... } } }

const express = require('express');
const { ccsSecrets } = require('../lib/fixtures');

const router = express.Router();

// GET /ccs/v4/secret/:integration_name
router.get('/v4/secret/:integration_name', (req, res) => {
  const name = req.params.integration_name;
  const blob = ccsSecrets[name];
  if (!blob) {
    return res.status(404).json({
      error: `no mock CCS secret for integration name '${name}'`,
      available: Object.keys(ccsSecrets)
    });
  }
  res.json({
    data: {
      [name]: blob
    }
  });
});

module.exports = router;
