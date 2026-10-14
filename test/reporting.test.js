import test from 'node:test';
import assert from 'node:assert/strict';
import { analyticsFor, validDate, requireSuperAdmin } from '../src/index.js';

function records(count, gapAt = -1, metric = 'profile_visits') {
  const out = [];
  const start = Date.parse('2026-09-01T00:00:00.000Z');
  for (let i = 0; i < count; i += 1) {
    if (i === gapAt) continue;
    const date = new Date(start + i * 86400000).toISOString().slice(0, 10);
    out.push({ date, platform: 'Instagram', metric, value: 100 + i });
  }
  return out;
}

test('validDate accepts only a real ISO calendar date', () => {
  assert.equal(validDate('2026-10-14'), true);
  assert.equal(validDate('2026-02-29'), false);
  assert.equal(validDate('14-10-2026'), false);
  assert.equal(validDate('2026-13-01'), false);
});

test('14 consecutive observations produce a growth comparison', () => {
  const report = analyticsFor(records(14));
  assert.equal(report.comparisons.length, 1);
  assert.equal(report.comparisons[0].previousPeriodValue, 103);
  assert.equal(report.comparisons[0].latestPeriodValue, 110);
  assert.equal(report.coverage[0].consecutive14DayWindow, true);
});

test('missing dates do not get treated as zero or produce a comparison', () => {
  const report = analyticsFor(records(14, 5));
  assert.equal(report.comparisons.length, 0);
  assert.equal(report.coverage[0].consecutive14DayWindow, false);
});

test('28 consecutive observations are required for a forecast', () => {
  assert.equal(analyticsFor(records(27)).forecasts.length, 0);
  const report = analyticsFor(records(28));
  assert.equal(report.forecasts.length, 1);
  assert.equal(report.forecasts[0].days, 7);
  assert.equal(report.forecasts[0].sourceVerified, false);
});

test('the server-side Super Admin UID allowlist is strict', () => {
  assert.doesNotThrow(() => requireSuperAdmin({ uid: 'owner-uid' }, { AJAYNXT_SUPER_ADMIN_UID: 'owner-uid' }));
  assert.throws(() => requireSuperAdmin({ uid: 'different-user' }, { AJAYNXT_SUPER_ADMIN_UID: 'owner-uid' }), { code: 'SUPER_ADMIN_REQUIRED' });
  assert.throws(() => requireSuperAdmin({ uid: 'owner-uid' }, {}), { code: 'SUPER_ADMIN_NOT_CONFIGURED' });
});
