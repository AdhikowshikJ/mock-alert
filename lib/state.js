// In-memory state for things that need a state machine.
// All cleared on restart — intentional for repeatable test runs.

// ─── Multi-step job state (nimbus brief 4) ──────────────────────────────────
// Status walks RUNNING → COMPLETED after 2 polls.
const jobs = new Map();

function createJob() {
  const id = `j-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  jobs.set(id, { state: 'RUNNING', polls: 0, createdAt: Date.now() });
  return id;
}

function getJob(id) {
  return jobs.get(id);
}

function pollJob(id) {
  const job = jobs.get(id);
  if (!job) return null;
  job.polls += 1;
  if (job.state !== 'COMPLETED' && job.polls >= 2) {
    job.state = 'COMPLETED';
  }
  return job;
}

// ─── Rate-limit state (pulse brief 7) ────────────────────────────────────────
// 5 requests per minute per token. Returns Retry-After hint when exceeded.
const RATE_WINDOW_MS = 60_000;
const RATE_LIMIT = 5;
const rateLimits = new Map();

function checkRateLimit(token) {
  const now = Date.now();
  let entry = rateLimits.get(token);
  if (!entry || now - entry.windowStart > RATE_WINDOW_MS) {
    entry = { count: 0, windowStart: now };
    rateLimits.set(token, entry);
  }
  entry.count += 1;
  if (entry.count > RATE_LIMIT) {
    const retryAfter = Math.max(
      1,
      Math.ceil((RATE_WINDOW_MS - (now - entry.windowStart)) / 1000)
    );
    return { allowed: false, retryAfter };
  }
  return { allowed: true };
}

// ─── Session login state (bastion brief 6) ───────────────────────────────────
const sessions = new Map();

function createSession() {
  const id = `sess-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  sessions.set(id, { createdAt: Date.now() });
  return id;
}

function hasSession(id) {
  return sessions.has(id);
}

// ─── OAuth2 token state (vortex brief 3) ─────────────────────────────────────
const oauthTokens = new Set();

function issueOauthToken() {
  const tok = `vortex-jwt-${Math.random().toString(36).slice(2, 16)}`;
  oauthTokens.add(tok);
  return tok;
}

function hasOauthToken(t) {
  return oauthTokens.has(t);
}

module.exports = {
  createJob, getJob, pollJob,
  checkRateLimit,
  createSession, hasSession,
  issueOauthToken, hasOauthToken
};
