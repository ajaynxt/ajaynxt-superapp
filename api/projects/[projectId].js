'use strict';

const { getFirebaseAdmin } = require('../_lib/firebase');
const { requireUser } = require('../_lib/auth');
const { requireProject, ADMIN_ROLES } = require('../_lib/access');
const { json, methodNotAllowed, sendError, requireAllowedOrigin } = require('../_lib/http');
const { parseJsonBody, cleanString } = require('../_lib/validation');

module.exports = async function projectDetail(req, res) {
  if (!['PATCH', 'DELETE'].includes(req.method)) return methodNotAllowed(res, ['PATCH', 'DELETE']);
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
    const { db, fieldValue } = getFirebaseAdmin();
    const access = await requireProject(db, user.uid, organizationId, projectId, ADMIN_ROLES);
    const auditRef = db.collection('organizations').doc(organizationId).collection('auditEvents').doc();

    if (req.method === 'DELETE') {
      await db.runTransaction(async (transaction) => {
        const existing = await transaction.get(access.projectRef);
        if (!existing.exists || existing.data().status === 'archived') {
          const error = new Error('Project was not found.');
          error.statusCode = 404;
          error.code = 'PROJECT_NOT_FOUND';
          throw error;
        }
        transaction.update(access.projectRef, {
          status: 'archived',
          archivedAt: fieldValue.serverTimestamp(),
          updatedAt: fieldValue.serverTimestamp(),
          archivedBy: user.uid
        });
        transaction.create(auditRef, {
          actorUid: user.uid,
          action: 'project.archived',
          resourceType: 'project',
          resourceId: projectId,
          createdAt: fieldValue.serverTimestamp()
        });
      });
      return json(res, 200, { archived: true, projectId });
    }

    const body = parseJsonBody(req, 16 * 1024);
    const name = cleanString(body.name, 'Project name', 90);
    const type = cleanString(body.type || access.project.type || 'Other', 'Project type', 60);
    const location = cleanString(body.location === undefined ? (access.project.location || '') : body.location, 'Project location', 120, false);
    const existing = await db.collection('organizations').doc(organizationId).collection('projects').limit(200).get();
    const duplicate = existing.docs.some((doc) => {
      if (doc.id === projectId || doc.data().status === 'archived') return false;
      return String(doc.data().name || '').trim().toLowerCase() === name.toLowerCase();
    });
    if (duplicate) {
      const error = new Error('A project with this name already exists in this workspace.');
      error.statusCode = 409;
      error.code = 'PROJECT_NAME_EXISTS';
      throw error;
    }

    const now = fieldValue.serverTimestamp();
    const batch = db.batch();
    batch.update(access.projectRef, { name, nameLower: name.toLowerCase(), type, location, updatedAt: now, updatedBy: user.uid });
    batch.create(auditRef, {
      actorUid: user.uid,
      action: 'project.updated',
      resourceType: 'project',
      resourceId: projectId,
      createdAt: now
    });
    await batch.commit();
    return json(res, 200, { project: { id: projectId, name, type, location, status: 'active' } });
  } catch (error) {
    return sendError(res, error);
  }
};
