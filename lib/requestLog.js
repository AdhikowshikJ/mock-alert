// Ring buffer of recent requests. Atlas talks to the mock; we record exactly
// what arrived (method, path, headers, query, body) so we can verify the
// generated template sent the right thing.

const MAX_ENTRIES = 1000;
let ring = [];

function requestLogger(req, res, next) {
  // Skip the debug + health endpoints — they're noise.
  if (req.path.startsWith('/_debug') || req.path === '/') return next();

  ring.push({
    ts:      new Date().toISOString(),
    method:  req.method,
    path:    req.originalUrl,
    headers: req.headers,
    query:   req.query,
    body:    req.body,
    cookies: req.cookies
  });
  if (ring.length > MAX_ENTRIES) ring.shift();
  next();
}

function getRecentRequests(limit = 100) {
  return ring.slice(-limit);
}

function clearRequests() {
  ring = [];
}

module.exports = { requestLogger, getRecentRequests, clearRequests };
