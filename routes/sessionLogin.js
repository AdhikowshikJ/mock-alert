// Brief 6 — session_login (bastion)
// POST /api/login returns session_id + Set-Cookie; subsequent calls use
// Cookie: SESSION=<id>. Offset/count pagination.

const express = require('express');
const { getSessionCookie } = require('../lib/auth');
const { createSession, hasSession } = require('../lib/state');
const { bastionEvents } = require('../lib/fixtures');

const router = express.Router();
const DEFAULT_COUNT = 500;
const MAX_COUNT = 1000;

// POST /bastion/api/login
// Form body: username=<u>&password=<p>
router.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'missing username or password' });
  }
  // Mock: any non-empty pair gets a session.
  const session_id = createSession();
  res.cookie('SESSION', session_id, { httpOnly: true, maxAge: 3600 * 1000 });
  res.json({ session_id, expires_in: 3600 });
});

// GET /bastion/api/events?from=<iso>&offset=<n>&count=<n>
router.get('/api/events', (req, res) => {
  const cookie = getSessionCookie(req);
  if (!cookie || !hasSession(cookie)) {
    return res.status(401).json({ error: 'invalid or missing SESSION cookie — POST /api/login first' });
  }

  const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
  const requestedCount = parseInt(req.query.count, 10) || DEFAULT_COUNT;
  const count = Math.min(Math.max(1, requestedCount), MAX_COUNT);

  const slice = bastionEvents.slice(offset, offset + count);

  res.json({
    events: slice,
    total_count: bastionEvents.length,
    offset,
    count: slice.length
  });
});

module.exports = router;
