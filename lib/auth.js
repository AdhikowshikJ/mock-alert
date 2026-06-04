// Shared header-extraction helpers. Each returns the extracted credential
// or null. None of these validate against a real secret store — any
// non-empty token is accepted. They validate SHAPE only (Bearer vs ApiToken
// vs Cookie), which is what we want to test in generated templates.

function getBearer(req) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return null;
  const tok = h.slice(7).trim();
  return tok || null;
}

function getApiToken(req) {
  // Literal `Authorization: ApiToken <tok>` (NOT Bearer). SentinelOne-style.
  const h = req.headers.authorization || '';
  if (!h.startsWith('ApiToken ')) return null;
  const tok = h.slice(9).trim();
  return tok || null;
}

function getApiKey(req) {
  // Custom `X-Api-Key: <tok>` header.
  const v = req.headers['x-api-key'];
  return (v && v.trim()) || null;
}

function getApiKeyAuthHeader(req) {
  // Literal `Authorization: ApiKey <tok>`. Different vendors use slightly
  // different literals — this one's for nimbus per its brief.
  const h = req.headers.authorization || '';
  if (!h.startsWith('ApiKey ')) return null;
  const tok = h.slice(7).trim();
  return tok || null;
}

function getSessionCookie(req) {
  return (req.cookies && req.cookies.SESSION) || null;
}

function unauthorized(res, msg) {
  return res.status(401).json({ error: msg || 'unauthorized' });
}

module.exports = {
  getBearer,
  getApiToken,
  getApiKey,
  getApiKeyAuthHeader,
  getSessionCookie,
  unauthorized
};
