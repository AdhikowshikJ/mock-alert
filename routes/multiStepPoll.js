// Brief 4 — multi_step_poll (nimbus)
// Submit job → poll status until COMPLETED → fetch results.

const express = require('express');
const { getApiKeyAuthHeader } = require('../lib/auth');
const { createJob, getJob, pollJob } = require('../lib/state');
const { nimbusEvents } = require('../lib/fixtures');

const router = express.Router();

function authOrReject(req, res) {
  const tok = getApiKeyAuthHeader(req);
  if (!tok) {
    res.status(401).json({ error: 'expected Authorization: ApiKey <token> (literal)' });
    return null;
  }
  return tok;
}

// POST /nimbus/api/search/jobs
// Form body: query=<spl>
router.post('/api/search/jobs', (req, res) => {
  if (!authOrReject(req, res)) return;
  if (!req.body || !req.body.query) {
    return res.status(400).json({ error: 'missing query in form body' });
  }
  const job_id = createJob();
  res.json({ job_id });
});

// GET /nimbus/api/search/jobs/:id/status
router.get('/api/search/jobs/:id/status', (req, res) => {
  if (!authOrReject(req, res)) return;
  const job = pollJob(req.params.id);
  if (!job) return res.status(404).json({ error: 'job not found' });

  res.json({
    job_id: req.params.id,
    state: job.state,
    progress: job.state === 'COMPLETED' ? 1.0 : Math.min(0.4 + job.polls * 0.25, 0.95)
  });
});

// GET /nimbus/api/search/jobs/:id/events?limit=<n>
router.get('/api/search/jobs/:id/events', (req, res) => {
  if (!authOrReject(req, res)) return;
  const job = getJob(req.params.id);
  if (!job) return res.status(404).json({ error: 'job not found' });
  if (job.state !== 'COMPLETED') {
    return res.status(400).json({
      error: 'job not COMPLETED yet — keep polling /status',
      state: job.state
    });
  }
  res.json({ events: nimbusEvents });
});

module.exports = router;
