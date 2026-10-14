'use strict';

const { getFirebaseAdmin } = require('../../_lib/firebase');
const { requireUser } = require('../../_lib/auth');
const { requireProject } = require('../../_lib/access');
const { json, methodNotAllowed, sendError, requireAllowedOrigin } = require('../../_lib/http');
const { validIsoDate } = require('../../_lib/validation');

function hasConsecutiveDates(dates) {
  for (let i = 1; i < dates.length; i += 1) {
    const prior = Date.parse(dates[i - 1] + 'T00:00:00.000Z');
    const next = Date.parse(dates[i] + 'T00:00:00.000Z');
    if (next - prior !== 86400000) return false;
  }
  return true;
}

function average(values) {
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function linearForecast(values) {
  const n = values.length;
  const xs = values.map((value, index) => index);
  const meanX = average(xs);
  const meanY = average(values);
  let numerator = 0;
  let denominator = 0;
  xs.forEach((x, index) => {
    numerator += (x - meanX) * (values[index] - meanY);
    denominator += (x - meanX) * (x - meanX);
  });
  const slope = denominator ? numerator / denominator : 0;
  const intercept = meanY - slope * meanX;
  const next = Array.from({ length: 7 }, (_, index) => Math.max(0, intercept + slope * (n + index)));
  return {
    method: 'Ordinary least-squares linear trend on 28 consecutive daily observations; 7-day point estimate.',
    days: 7,
    averagePerDay: average(next),
    dailyEstimates: next
  };
}

function buildAnalytics(records) {
  const bySeries = new Map();
  records.forEach((record) => {
    const key = record.platform.toLowerCase() + '|||' + record.metric.toLowerCase();
    if (!bySeries.has(key)) bySeries.set(key, { platform: record.platform, metric: record.metric, valuesByDate: new Map() });
    bySeries.get(key).valuesByDate.set(record.date, Number(record.value));
  });

  const comparisons = [];
  const forecasts = [];
  const coverage = [];

  for (const series of bySeries.values()) {
    const dates = Array.from(series.valuesByDate.keys()).sort();
    const values = dates.map((date) => series.valuesByDate.get(date));
    coverage.push({
      platform: series.platform,
      metric: series.metric,
      observations: dates.length,
      firstDate: dates[0] || null,
      latestDate: dates[dates.length - 1] || null,
      consecutive14DayWindow: dates.length >= 14 && hasConsecutiveDates(dates.slice(-14)),
      consecutive28DayWindow: dates.length >= 28 && hasConsecutiveDates(dates.slice(-28))
    });

    if (dates.length >= 14) {
      const windowDates = dates.slice(-14);
      if (hasConsecutiveDates(windowDates)) {
        const windowValues = windowDates.map((date) => series.valuesByDate.get(date));
        const snapshotMetric = /(followers?|subscribers?|members?_count|total_followers)/i.test(series.metric);
        const previous = snapshotMetric ? windowValues[6] : average(windowValues.slice(0, 7));
        const latest = snapshotMetric ? windowValues[13] : average(windowValues.slice(7, 14));
        comparisons.push({
          platform: series.platform,
          metric: series.metric,
          comparisonType: snapshotMetric ? 'snapshot_first_window_end_vs_latest_window_end' : 'daily_average_latest_7_vs_previous_7',
          previousPeriodValue: previous,
          latestPeriodValue: latest,
          absoluteChange: latest - previous,
          percentageChange: previous === 0 ? null : ((latest / previous) - 1) * 100,
          startDate: windowDates[0],
          previousPeriodEnd: windowDates[6],
          latestPeriodStart: windowDates[7],
          endDate: windowDates[13],
          sourceVerified: false
        });
      }
    }

    if (dates.length >= 28) {
      const windowDates = dates.slice(-28);
      if (hasConsecutiveDates(windowDates)) {
        const windowValues = windowDates.map((date) => series.valuesByDate.get(date));
        const forecast = linearForecast(windowValues);
        const recentAverage = average(windowValues.slice(-7));
        forecasts.push({
          platform: series.platform,
          metric: series.metric,
          basedOnStartDate: windowDates[0],
          basedOnEndDate: windowDates[27],
          recent7DayAverage: recentAverage,
          ...forecast,
          projectedAverageChangePercent: recentAverage === 0 ? null : ((forecast.averagePerDay / recentAverage) - 1) * 100,
          sourceVerified: false,
          disclaimer: 'Estimate only. This simple trend does not model seasonality, promotions, stock-outs, platform ranking changes or uncertainty.'
        });
      }
    }
  }

  return { coverage, comparisons, forecasts };
}

module.exports = async function projectReport(req, res) {
  if (req.method !== 'GET') return methodNotAllowed(res, ['GET']);
  if (!requireAllowedOrigin(req, res)) return;

  try {
    const user = await requireUser(req);
    const query = req.query || {};
    const organizationId = query.organizationId;
    const projectId = query.projectId;
    if (typeof organizationId !== 'string' || !organizationId || typeof projectId !== 'string' || !projectId) {
      const error = new Error('organizationId and projectId are required.');
      error.statusCode = 400;
      error.code = 'PROJECT_SCOPE_REQUIRED';
      throw error;
    }

    const { db } = getFirebaseAdmin();
    const access = await requireProject(db, user.uid, organizationId, projectId);
    const startDate = query.startDate;
    const endDate = query.endDate;
    if (startDate && !validIsoDate(startDate)) {
      const error = new Error('startDate must use YYYY-MM-DD format.');
      error.statusCode = 400;
      error.code = 'INVALID_START_DATE';
      throw error;
    }
    if (endDate && !validIsoDate(endDate)) {
      const error = new Error('endDate must use YYYY-MM-DD format.');
      error.statusCode = 400;
      error.code = 'INVALID_END_DATE';
      throw error;
    }
    if (startDate && endDate && startDate > endDate) {
      const error = new Error('startDate must be on or before endDate.');
      error.statusCode = 400;
      error.code = 'INVALID_DATE_RANGE';
      throw error;
    }

    let limit = Number.parseInt(String(query.limit || '2000'), 10);
    if (!Number.isFinite(limit) || limit < 1) limit = 2000;
    limit = Math.min(limit, 2000);

    let queryRef = access.projectRef.collection('metrics');
    if (startDate) queryRef = queryRef.where('date', '>=', startDate);
    if (endDate) queryRef = queryRef.where('date', '<=', endDate);
    const snapshot = await queryRef.orderBy('date', 'desc').limit(limit).get();
    const records = snapshot.docs.map((doc) => {
      const data = doc.data();
      return {
        id: doc.id,
        date: data.date,
        platform: data.platform,
        metric: data.metric,
        value: data.value,
        source: data.source || null,
        sourceVerified: data.sourceVerified === true,
        importedAt: data.importedAt && typeof data.importedAt.toDate === 'function' ? data.importedAt.toDate().toISOString() : null
      };
    });

    const analytics = buildAnalytics(records.slice().reverse());
    return json(res, 200, {
      project: { id: projectId, name: access.project.name },
      organizationId,
      generatedAt: new Date().toISOString(),
      recordCount: records.length,
      dataCoverage: {
        firstDate: records.length ? records.reduce((a, r) => r.date < a ? r.date : a, records[0].date) : null,
        latestDate: records.length ? records.reduce((a, r) => r.date > a ? r.date : a, records[0].date) : null,
        limitApplied: records.length === limit
      },
      ...analytics,
      records,
      disclaimers: [
        'This report contains user-imported records not independently verified against provider systems.',
        'Missing dates are not treated as zero; comparisons require a complete consecutive window.',
        'Trend estimates are not promises and do not establish causation.',
        'Revenue must not be described as profit without validated costs.'
      ]
    });
  } catch (error) {
    return sendError(res, error);
  }
};
