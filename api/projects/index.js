'use strict';

const crypto = require('node:crypto');
const { getFirebaseAdmin } = require('../_lib/firebase');
const { requireUser } = require('../_lib/auth');
const { requireOrganization, ADMIN_ROLES } = require('../_lib/access');
const { json, methodNotAllowed, sendError, requireAllowedOrigin } = require('../_lib/http');
const { parseJsonBody, cleanString } = require('../_lib/validation');

module.exports = async function projects(req, res) {
  if (!['GET', 'POST'].includes(req.method)) return methodNotAllowed(res, ['GET', 'POST']);
  if (!requireAllowedOrigin(req, res)) return;

  try {
    const user = await requireUser(req);
    const organizationId = req.query && req.query.organizationId;
    if (typeof organizationId !== 'string' || !organizationId) {
      const error = new Error('organizationId query parameter is required.');
      error.statusCode = 400;
      error.code = 'ORGANIZATION_ID_REQUIRED';
      throw error;
    }
    const { db, fieldValue } = getFirebaseAdmin();
    const allowed = req.method === 'GET' ? undefined : ADMIN_ROLES;
    await requireOrganization(db, user.uid, organizationId, allowed);

    const projectsRef = db.collection('organizations').doc(organizationId).collection('projects');
    if (req.method === 'GET') {
      const snapshot = await projectsRef.limit(200).get();
      const result = snapshot.docs
        .map((doc) => ({ id: doc.id, ...doc.data() }))
        .filter((item) => item.status !== 'archived')
        .map((item) => ({
          id: item.id,
          name: item.name,
          type: item.type || 'Other',
          location: item.location || '',
          status: item.status || 'active',
          createdAt: item.createdAt && typeof item.createdAt.toDate === 'function' ? item.createdAt.toDate().toISOString() : null
        }));
      return json(res, 200, { projects: result });
    }

    const body = parseJsonBody(req, 16 * 1024);
    const name = cleanString(body.name, 'Project name', 90);
    const type = cleanString(body.type || 'Other', 'Project type', 60);
    const location = cleanString(body.location || '', 'Project location', 120, false);
    const existing = await projectsRef.limit(200).get();
    const duplicate = existing.docs.some((doc) => {
      const data = doc.data();
      return data.status !== 'archived' && String(data.name || '').trim().toLowerCase() === name.toLowerCase();
    });
    if (duplicate) {
      const error = new Error('A project with this name already exists in this workspace.');
      error.statusCode = 409;
      error.code = 'PROJECT_NAME_EXISTS';
      throw error;
    }

    const projectRef = projectsRef.doc(crypto.randomUUID());
    const auditRef = db.collection('organizations').doc(organizationId).collection('auditEvents').doc(crypto.randomUUID());
    const now = fieldValue.serverTimestamp();
    const projectData = {
      name,
      nameLower: name.toLowerCase(),
      type,
      location,
      status: 'active',
      createdBy: user.uid,
      createdAt: now,
      updatedAt: now,
      schemaVersion: 1
    };
    const batch = db.batch();
    batch.create(projectRef, projectData);
    batch.create(auditRef, {
      actorUid: user.uid,
      action: 'project.created',
      resourceType: 'project',
      resourceId: projectRef.id,
      createdAt: now
    });
    await batch.commit();

    return json(res, 201, {
      project: {
        id: projectRef.id,
        name,
        type,
        location,
        status: 'active',
        createdAt: new Date().toISOString()
      }
    });
  } catch (error) {
    return sendError(res, error);
  }
};
