'use strict';

const { getFirebaseAdmin } = require('../../_lib/firebase');
const { requireUser } = require('../../_lib/auth');
const { requireProject } = require('../../_lib/access');
const { json, methodNotAllowed, sendError, requireAllowedOrigin } = require('../../_lib/http');
const { validIsoDate } = require('../../_lib/validation');

module.exports = async function projectMetrics(req, res) {
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

    let limit = Number.parseInt(String(query.limit || '500'), 10);
    if (!Number.isFinite(limit) || limit < 1) limit = 500;
    limit = Math.min(limit, 1000);

    let collection = access.projectRef.collection('metrics');
    if (startDate) collection = collection.where('date', '>=', startDate);
    if (endDate) collection = collection.where('date', '<=', endDate);
    collection = collection.orderBy('date', 'desc').limit(limit);
    const snapshot = await collection.get();
    const metrics = snapshot.docs.map((doc) => {
      const data = doc.data();
      return {
        id: doc.id,
        date: data.date,
        platform: data.platform,
        metric: data.metric,
        value: data.value,
        source: data.source || null,
        importedAt: data.importedAt && typeof data.importedAt.toDate === 'function' ? data.importedAt.toDate().toISOString() : null
      };
    });
    return json(res, 200, {
      organizationId,
      projectId,
      projectName: access.project.name,
      count: metrics.length,
      metrics,
      note: 'Values are only as verified as their provider/API or import source.'
    });
  } catch (error) {
    return sendError(res, error);
  }
};
