// Unified per-vendor alert store — the heart of "one vendor, both directions".
//
// Pull endpoints READ from here; writeback endpoints MUTATE the same records.
// So the alert id you pull is the id you can close, and a re-pull (or
// /_debug/alerts/:vendor) shows the status flip — proving the full round-trip
// against a single vendor.
//
// All in-memory, reseeded on restart or via POST /_debug/reseed.

const fx = require('./fixtures');

// vendor -> array of alert objects (mutable)
const stores = new Map();

function seedAll() {
  stores.set('falcon',   fx.falconAlerts().map(a => ({ ...a })));
  stores.set('sentryx',  fx.sentryxThreats().map(a => ({ ...a })));
  stores.set('skylux',   fx.skyluxIssues().map(a => ({ ...a })));
  stores.set('ironclad', fx.ironcladDetections().map(a => ({ ...a })));
  stores.set('warden',   fx.wardenEvents().map(a => ({ ...a })));
  stores.set('rampart',  fx.rampartDetections().map(a => ({ ...a })));
}
seedAll();

function all(vendor) {
  return stores.get(vendor) || [];
}

// Cursor/offset slice helper. Returns { items, nextOffset|null }.
function page(vendor, offset, limit) {
  const list = all(vendor);
  const start = Math.max(0, offset || 0);
  const items = list.slice(start, start + limit);
  const next = start + limit < list.length ? start + limit : null;
  return { items, next, total: list.length };
}

// Find by an arbitrary id field (composite_id / threat_id / id ...).
function find(vendor, idField, id) {
  return all(vendor).find(a => String(a[idField]) === String(id)) || null;
}

// Apply a patch (e.g. { status: 'closed' }) to one alert. Returns the updated
// alert, or null if not found.
function patch(vendor, idField, id, patchObj) {
  const a = find(vendor, idField, id);
  if (!a) return null;
  Object.assign(a, patchObj);
  return a;
}

module.exports = { seedAll, all, page, find, patch };
