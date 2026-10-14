'use strict';

const crypto = require('node:crypto');
const { getFirebaseAdmin } = require('../../_lib/firebase');
const { requireUser } = require('../../_lib/auth');
const { requireProject, WRITE_ROLES } = require('../../_lib/access');
const { json, methodNotAllowed, sendError, requireAllowedOrigin } = require('../../_lib/http');
const { parseJsonBody, cleanString, validIsoDate } = require('../../_lib/validation');

function recordId(record) {
  const key = [record.date, record.platform.toLowerCase(), record.metric.toLowerCase()].join('|');
  return crypto.createHash('sha256').update(key, 'utf8').digest('hex');
}

module.exports = async function importMetrics(req, res) {
  if (req.method !== 'POST') return methodNotAllowed(res, ['POST']);
  if (!requireAllowedOrigin(req, res)) return;

  try {
    const user = await requireUser(req);
    const { db, fieldValue } = getFirebaseAdmin();
    const body = parseJsonBody(req, 256 * 1024);
    const organizationId = cleanString(body.organizationId, 'organizationId', 128);
    const projectId = req.query && req.query.projectId;
    if (typeof projectId !== 'string' || !projectId) {
      const error = new Error('projectId path parameter is required.');
      error.statusCode = 400;
      error.code = 'PROJECT_ID_REQUIRED';
      throw error;
    }
    const access = await requireProject(db, user.uid, organizationId, projectId, WRITE_ROLES);
    if (!Array.isArray(body.records) || body.records.length < 1 || body.records.length > 300) {
      const error = new Error('records must contain between 1 and 300 observations per import.');
      error.statusCode = 400;
      error.code = 'INVALID_RECORD_COUNT';
      throw error;
    }

    const records = body.records.map((item, index) => {
      if (!item || typeof item !== 'object' || Array.isArray(item)) {
        const error = new Error('Record ' + (index + 1) + ' must be an object.');
        error.statusCode = 400;
        error.code = 'INVALID_RECORD';
        throw error;
      }
      const date = item.date;
      if (!validIsoDate(date)) {
        const error = new Error('Record ' + (index + 1) + ' has an invalid date; use YYYY-MM-DD.');
        error.statusCode = 400;
        error.code = 'INVALID_DATE';
        throw error;
      }
      const platform = cleanString(item.platform, 'platform', 60);
      const metric = cleanString(item.metric, 'metric', 64).toLowerCase().replace(/\s+/g, '_');
      if (!/^[a-z][a-z0-9_]{0,63}$/.test(metric)) {
        const error = new Error('Metric names must use lowercase letters, numbers and underscores, starting with a letter.');
        error.statusCode = 400;
        error.code = 'INVALID_METRIC';
        throw error;
      }
      const value = typeof item.value === 'number' ? item.value : Number(item.value);
      if (!Number.isFinite(value) || value < 0 || value > 1e15) {
        const error = new Error('Metric values must be finite, non-negative numbers no greater than 1e15.');
        error.statusCode = 400;
        error.code = 'INVALID_METRIC_VALUE';
        throw error;
      }
      const source = cleanString(item.source || 'User CSV import', 'source', 160);
      return { date, platform, metric, value, source };
    });

    const keys = new Set();
    for (const record of records) {
      const key = recordId(record);
      if (keys.has(key)) {
        const error = new Error('The import contains duplicate date/platform/metric observations.');
        error.statusCode = 409;
        error.code = 'DUPLICATE_INPUT_RECORD';
        throw error;
      }
      keys.add(key);
    }

    const metricsRef = access.projectRef.collection('metrics');
    const refs = records.map((record) => metricsRef.doc(recordId(record)));
    const auditRef = db.collection('organizations').doc(organizationId).collection('auditEvents').doc(crypto.randomUUID());
    await db.runTransaction(async (transaction) => {
      const existing = await transaction.getAll(...refs);
      if (existing.some((snapshot) => snapshot.exists)) {
        const error = new Error('One or more observations already exist. Duplicate records are not overwritten.');
        error.statusCode = 409;
        error.code = 'DUPLICATE_STORED_RECORD';
        throw error;
      }

      records.forEach((record, index) => {
        transaction.create(refs[index], {
          ...record,
          importedBy: user.uid,
          importedAt: fieldValue.serverTimestamp(),
          sourceVerified: false,
          schemaVersion: 1
        });
      });
      transaction.create(auditRef, {
        actorUid: user.uid,
        action: 'metrics.imported',
        resourceType: 'project',
        resourceId: projectId,
        recordCount: records.length,
        createdAt: fieldValue.serverTimestamp()
      });
    });

    return json(res, 201, {
      imported: records.length,
      projectId,
      organizationId,
      sourceVerified: false,
      message: 'Records imported. Their source has not been independently verified; missing dates are not treated as zero.'
    });
  } catch (error) {
    return sendError(res, error);
  }
};
