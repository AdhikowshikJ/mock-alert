// Canned alert / event data for each vendor + CCS v4 secret blobs.
// Sizes chosen to exercise pagination across multiple pages where relevant.

// ─── Vanilla Bearer (brief 1) — no pagination, 5 alerts ──────────────────────
const vanillaBearerAlerts = [
  { id: 'vb-001', created_at: '2026-05-30T12:34:56Z', severity: 'high',     rule_name: 'Suspicious Login',           src_ip: '10.0.0.42',   user: 'jdoe' },
  { id: 'vb-002', created_at: '2026-05-30T12:35:10Z', severity: 'medium',   rule_name: 'Multiple Failed Logins',     src_ip: '10.0.0.42',   user: 'jdoe' },
  { id: 'vb-003', created_at: '2026-05-30T12:36:22Z', severity: 'low',      rule_name: 'Unusual Geo',                src_ip: '203.0.113.5', user: 'asmith' },
  { id: 'vb-004', created_at: '2026-05-30T12:37:00Z', severity: 'high',     rule_name: 'Privilege Escalation',       src_ip: '10.0.0.99',   user: 'svc-deploy' },
  { id: 'vb-005', created_at: '2026-05-30T12:38:15Z', severity: 'critical', rule_name: 'Lateral Movement Detected',  src_ip: '10.0.0.42',   user: 'jdoe' }
];

// ─── Cobalt (brief 2) — 30 detections, 10/page, has_more boolean ────────────
const cobaltDetections = Array.from({ length: 30 }, (_, i) => ({
  id: `det-${String(i + 1).padStart(4, '0')}`,
  occurred_at: `2026-05-30T${String(12 + Math.floor(i / 10)).padStart(2, '0')}:${String((i * 7) % 60).padStart(2, '0')}:56Z`,
  severity: ['low', 'medium', 'high', 'critical'][i % 4],
  category: ['exfiltration', 'lateral_movement', 'credential_access', 'persistence'][i % 4],
  asset_id: `i-${String(i + 100).padStart(4, '0')}`,
  description: `Detection ${i + 1}: anomalous activity`
}));

// ─── Vortex (brief 3) — 25 threats, 10/page, cursor pagination ──────────────
const vortexThreats = Array.from({ length: 25 }, (_, i) => ({
  id: `thr-${'abcd'[i % 4].repeat(4)}-${String(i + 1000).padStart(4, '0')}`,
  detected_at: `2026-05-30T12:${String((i * 3) % 60).padStart(2, '0')}:56Z`,
  severity: ['low', 'medium', 'high'][i % 3],
  name: ['PowerShell.Suspicious.Encoded', 'Trojan.Generic', 'Backdoor.Linux'][i % 3],
  endpoint_id: `ep-${String(i).padStart(4, '0')}`,
  hostname: `win10-prod-${String(i % 10).padStart(2, '0')}`
}));

// ─── Nimbus (brief 4) — 100 events, returned all-at-once after poll ─────────
const nimbusEvents = Array.from({ length: 100 }, (_, i) => ({
  event_id: `evt-${String(i + 1).padStart(4, '0')}`,
  ts: `2026-05-30T12:${String(i % 60).padStart(2, '0')}:56Z`,
  severity: ['low', 'medium', 'high'][i % 3],
  rule: 'Failed login from unusual geo',
  user: `user${i % 10}`,
  geo_country: ['US', 'RU', 'CN', 'DE'][i % 4]
}));

// ─── Aegis (brief 5) — 15 alert IDs, 5/page on list; detail on demand ──────
const aegisAlertIds = Array.from({ length: 15 }, (_, i) => `a-${String(i + 1).padStart(3, '0')}`);

function aegisAlertDetail(id) {
  return {
    id,
    created_at: '2026-05-30T12:34:56Z',
    severity: 'high',
    type: 'lateral_movement',
    source_host: `host-${id.slice(2)}`,
    target_host: 'dc-01',
    raw_evidence: '<binary>'
  };
}

// ─── Bastion (brief 6) — 1247 events, offset/count pagination ────────────────
const bastionEvents = Array.from({ length: 1247 }, (_, i) => ({
  event_id: `ev-${String(i + 1).padStart(5, '0')}`,
  ts: `2026-05-30T${String(12 + Math.floor(i / 60) % 24).padStart(2, '0')}:${String(i % 60).padStart(2, '0')}:56Z`,
  type: ['authentication_failure', 'authentication_success', 'lockout'][i % 3],
  severity: 'low',
  src_ip: `192.168.1.${(i % 254) + 1}`,
  user: `user${i % 20}`
}));

// ─── Pulse (brief 7) — 8 detections, returned when rate limit allows ────────
const pulseDetections = Array.from({ length: 8 }, (_, i) => ({
  id: `d-pulse-${String(i + 1).padStart(3, '0')}`,
  time: `2026-05-30T12:${String(i * 5).padStart(2, '0')}:56Z`,
  severity: ['medium', 'high'][i % 2],
  tactic: ['credential_access', 'discovery', 'persistence'][i % 3],
  host: `endpoint-${i + 1}`
}));

// ─── Helix (brief 8) — 10 alerts, 5/page; assets ending '00' return 404 ─────
// Asset ID `i-000600` will 404; others will succeed. Pattern is deterministic
// so tests can assert on it.
const helixAlerts = Array.from({ length: 10 }, (_, i) => {
  const baseId = String(i + 1).padStart(4, '0');
  // Make the 6th alert's asset deliberately point at a non-existent asset (ends in '00')
  const assetTail = (i === 5) ? '00' : '';
  return {
    id: `alert-${String(9000 + i + 1).padStart(4, '0')}`,
    timestamp: `2026-05-30T12:${String(i * 5).padStart(2, '0')}:56Z`,
    severity: ['medium', 'high', 'critical'][i % 3],
    type: 'malware_detected',
    asset_id: `i-${baseId}${assetTail}`,
    indicator: `sha256:${'a'.repeat(40)}${i}`
  };
});

// ─── UNIFIED vendors (one vendor, both pull + writeback, shared alert store) ──
// These are functions (not const arrays) so lib/alertStore.js can reseed fresh
// copies. Each alert carries a mutable `status` the writeback flips.

// falcon (CrowdStrike-shape) — OAuth2 + cursor pull + single-call close.
// 12 detections, paginated 5/page; id field = composite_id; status open→closed.
function falconAlerts() {
  return Array.from({ length: 12 }, (_, i) => ({
    composite_id: `falcon:${String(i + 1).padStart(4, '0')}:det`,
    created_at: `2026-06-01T12:${String((i * 4) % 60).padStart(2, '0')}:00Z`,
    severity: ['low', 'medium', 'high', 'critical'][i % 4],
    tactic: ['credential_access', 'lateral_movement', 'persistence'][i % 3],
    device_id: `dev-${String(i + 100).padStart(4, '0')}`,
    status: 'open'
  }));
}

// sentryx (SentinelOne-shape) — ApiToken + offset pull + multi-step close+note.
// 12 threats, 6/page; id field = threat_id; status active→resolved + verdict.
function sentryxThreats() {
  return Array.from({ length: 12 }, (_, i) => ({
    threat_id: `thr-${String(i + 1).padStart(5, '0')}`,
    created_at: `2026-06-01T13:${String((i * 5) % 60).padStart(2, '0')}:00Z`,
    severity: ['low', 'medium', 'high'][i % 3],
    classification: 'Malware',
    agent_id: `agent-${String(i).padStart(4, '0')}`,
    status: 'active',
    analystVerdict: 'undefined'
  }));
}

// skylux (Wiz-shape) — OAuth2 + GraphQL for both pull (query) and writeback (mutation).
// 8 issues; id field = id; status OPEN→IN_PROGRESS.
function skyluxIssues() {
  return Array.from({ length: 8 }, (_, i) => ({
    id: `iss-${String(i + 1).padStart(4, '0')}`,
    created_at: `2026-06-01T14:${String((i * 7) % 60).padStart(2, '0')}:00Z`,
    severity: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'][i % 4],
    title: `Risky configuration ${i + 1}`,
    status: 'OPEN'
  }));
}

// ironclad — X-Api-Key + has_more pull + single close by id. 14 detections, 5/page.
// id field = id; status new→closed. Edge: close unknown id → 404; re-close → no-op.
function ironcladDetections() {
  return Array.from({ length: 14 }, (_, i) => ({
    id: `ic-${String(i + 1).padStart(4, '0')}`,
    occurred_at: `2026-06-01T15:${String((i * 4) % 60).padStart(2, '0')}:00Z`,
    severity: ['low', 'medium', 'high', 'critical'][i % 4],
    category: ['exfiltration', 'persistence', 'discovery'][i % 3],
    status: 'new'
  }));
}

// warden — session-cookie auth + offset pull + cookie-auth close. 20 events, 8/page.
// id field = event_id; status open→closed. Edge: missing/invalid cookie → 401.
function wardenEvents() {
  return Array.from({ length: 20 }, (_, i) => ({
    event_id: `wd-${String(i + 1).padStart(5, '0')}`,
    ts: `2026-06-01T16:${String(i % 60).padStart(2, '0')}:00Z`,
    type: ['auth_failure', 'lockout', 'policy_violation'][i % 3],
    severity: ['low', 'medium', 'high'][i % 3],
    user: `user${i % 8}`,
    status: 'open'
  }));
}

// rampart — Bearer static + single pull + single close, rate-limited 5/min on BOTH.
// 6 detections; id field = id; status open→resolved. Edge: 429 Retry-After on writeback too.
function rampartDetections() {
  return Array.from({ length: 6 }, (_, i) => ({
    id: `rp-${String(i + 1).padStart(3, '0')}`,
    time: `2026-06-01T17:${String(i * 5).padStart(2, '0')}:00Z`,
    severity: ['medium', 'high'][i % 2],
    tactic: ['credential_access', 'persistence'][i % 2],
    status: 'open'
  }));
}

// ─── CCS v4 secret blobs per integration name ────────────────────────────────
// Atlas hits a real CCS v4 endpoint in prod. This is here for:
//   (a) documenting what each vendor's secret blob should look like
//   (b) local execution / light-executor scenarios where we replace CCS
// `instance_url` etc. point at this same mock service so generated templates
// route back here.
function base(suffix) {
  const root = process.env.PUBLIC_BASE_URL || 'http://localhost:3000';
  return `${root}${suffix}`;
}

const ccsSecrets = {
  VANILLA_BEARER: {
    instance_url: base('/vanilla-bearer'),
    api_token:    'mock-vanilla-bearer-token-abc123'
  },
  COBALT: {
    console_url:  base('/cobalt'),
    api_token:    'mock-cobalt-token-xyz789'
  },
  VORTEX: {
    api_url:       base('/vortex'),
    auth_url:      base('/vortex'),
    client_id:     'mock-vortex-client',
    client_secret: 'mock-vortex-secret'
  },
  NIMBUS: {
    instance_url: base('/nimbus'),
    api_token:    'mock-nimbus-apikey-123'
  },
  AEGIS: {
    instance_url: base('/aegis'),
    api_token:    'mock-aegis-key-321'
  },
  BASTION: {
    instance_url: base('/bastion'),
    username:     'mock-admin',
    password:     'mock-password'
  },
  PULSE: {
    instance_url: base('/pulse'),
    api_token:    'mock-pulse-key-654'
  },
  HELIX: {
    instance_url: base('/helix'),
    api_token:    'mock-helix-token-987'
  },

  // ─── WRITEBACK vendors (close-alert / response-action targets) ─────────────
  // These back the /sentinelshield, /nimbusguard, /threatnexus, /lumen writeback
  // routes. Field names mirror what the write-backs skill's generated handlers
  // read from .out.handler.http.http_get_sensor_secret_v4.data.<INTEGRATION_NAME>.
  SENTINELSHIELD_EDR: {              // archetype A — static API key, single call
    base_url: base('/sentinelshield'),
    api_key:  'mock-sentinelshield-key-aaa111'
  },
  NIMBUSGUARD_CLOUD: {               // archetype B — OAuth2 client_credentials
    base_url:      base('/nimbusguard'),
    client_id:     'mock-nimbusguard-client',
    client_secret: 'mock-nimbusguard-secret'
  },
  THREATNEXUS_XDR: {                 // archetype C — ApiToken, multi-step close + note
    base_url:   base('/threatnexus'),
    api_token:  'mock-threatnexus-token-ccc333',
    account_id: 'act-889900'
  },
  LUMEN_CNAPP: {                     // archetype D — OAuth2 + GraphQL mutation
    graphql_endpoint: base('/lumen/graphql'),
    auth_url:         base('/lumen'),
    client_id:        'mock-lumen-client',
    client_secret:    'mock-lumen-secret'
  },

  // ─── UNIFIED vendors — one secret powers BOTH pull and writeback ───────────
  FALCON: {                          // OAuth2 + cursor pull + single-call close
    base_url:      base('/falcon'),
    auth_url:      base('/falcon'),
    client_id:     'mock-falcon-client',
    client_secret: 'mock-falcon-secret'
  },
  SENTRYX: {                         // ApiToken + offset pull + multi-step close+note
    base_url:   base('/sentryx'),
    api_token:  'mock-sentryx-token-sss111',
    account_id: 'acct-770011'
  },
  SKYLUX: {                          // OAuth2 + GraphQL pull (query) & writeback (mutation)
    graphql_endpoint: base('/skylux/graphql'),
    auth_url:         base('/skylux'),
    client_id:        'mock-skylux-client',
    client_secret:    'mock-skylux-secret'
  },
  IRONCLAD: {                        // X-Api-Key + has_more pull + close (404 / idempotent edges)
    base_url: base('/ironclad'),
    api_key:  'mock-ironclad-key-iii222'
  },
  WARDEN: {                          // session-cookie + offset pull + cookie-auth close
    base_url: base('/warden'),
    username: 'mock-warden-admin',
    password: 'mock-warden-pass'
  },
  RAMPART: {                         // Bearer static + single pull/close, rate-limited 5/min
    base_url:  base('/rampart'),
    api_token: 'mock-rampart-token-rrr333'
  }
};

module.exports = {
  vanillaBearerAlerts,
  cobaltDetections,
  vortexThreats,
  nimbusEvents,
  aegisAlertIds,
  aegisAlertDetail,
  bastionEvents,
  pulseDetections,
  helixAlerts,
  falconAlerts,
  sentryxThreats,
  skyluxIssues,
  ironcladDetections,
  wardenEvents,
  rampartDetections,
  ccsSecrets
};
