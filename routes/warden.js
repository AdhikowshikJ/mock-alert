// Unified vendor: warden
// Session-login (cookie) + offset pull + cookie-authed writeback.
// The SAME session cookie authorizes both pull and close.
// Failure edge: missing / unknown SESSION cookie → 401 on both pull and writeback.

const express = require('express');
const { getSessionCookie, unauthorized } = require('../lib/auth');
const { createSession, hasSession, recordWriteback } = require('../lib/state');
const store = require('../lib/alertStore');

const router = express.Router();
const COUNT = 8;

// POST /warden/login   { username, password } → Set-Cookie: SESSION
router.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username + password required' });
  const sid = createSession();
  res.cookie('SESSION', sid, { httpOnly: true });
  res.json({ ok: true });
});

function requireSession(req, res) {
  const sid = getSessionCookie(req);
  if (!sid || !hasSession(sid)) { unauthorized(res, 'missing/invalid SESSION cookie (POST /warden/login first)'); return false; }
  return true;
}

// GET /warden/events?offset=0&count=8   — PULL (offset/count pagination)
router.get('/events', (req, res) => {
  if (!requireSession(req, res)) return;
  const offset = parseInt(req.query.offset) || 0;
  const count = Math.min(parseInt(req.query.count) || COUNT, 100);
  const { items, next, total } = store.page('warden', offset, count);
  res.json({ events: items, total, offset, next_offset: next });
});

// POST /warden/events/:id/close   — WRITEBACK (cookie-authed)
router.post('/events/:id/close', (req, res) => {
  if (!requireSession(req, res)) return;
  const { id } = req.params;
  const disposition = (req.body && req.body.disposition) || 'closed';
  const updated = store.patch('warden', 'event_id', id, { status: 'closed', disposition });
  if (!updated) return res.status(404).json({ error: 'event not found', id });
  recordWriteback({ vendor: 'warden', kind: 'unified', id, disposition });
  res.json({ ok: true, id, disposition });
});

module.exports = router;
