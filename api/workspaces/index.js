'use strict';

const crypto = require('node:crypto');
const { getFirebaseAdmin } = require('../_lib/firebase');
const { requireUser } = require('../_lib/auth');
const { json, methodNotAllowed, parseJsonBody, cleanString, sendError, requireAllowedOrigin } = (() => {
  const http = require('../_lib/http');
  const validation = require('../_lib/validation');
  return { ...http, ...validation };
})();

module.exports = async function workspaces(req, res) {
  if (!['GET', 'POST'].includes(req.method)) return methodNotAllowed(res, ['GET', 'POST']);
  if (!requireAllowedOrigin(req, res)) return;

  try {
    const user = await requireUser(req);
    const { db, fieldValue } = getFirebaseAdmin();
    const userRef = db.collection('users').doc(user.uid);
    const membershipsRef = userRef.collection('organizations');

    if (req.method === 'GET') {
      const memberships = await membershipsRef.limit(50).get();
      const workspaces = [];
      for (const item of memberships.docs) {
        const membership = item.data();
        if (membership.status !== 'active') continue;
        const org = await db.collection('organizations').doc(item.id).get();
        if (!org.exists || org.data().status !== 'active') continue;
        workspaces.push({
          id: org.id,
          name: org.data().name,
          role: membership.role,
          createdAt: org.data().createdAt && typeof org.data().createdAt.toDate === 'function'
            ? org.data().createdAt.toDate().toISOString() : null
        });
      }
      return json(res, 200, { workspaces });
    }

    const body = parseJsonBody(req, 16 * 1024);
    const name = cleanString(body.name || 'AJAYNXT Workspace', 'Workspace name', 100);
    // One default agency workspace per user for initial onboarding. Additional
    // businesses are projects within that workspace, not separate tenants.
    const organizationId = 'org_' + user.uid;
    const orgRef = db.collection('organizations').doc(organizationId);
    const userMembershipRef = membershipsRef.doc(organizationId);
    const orgMemberRef = orgRef.collection('members').doc(user.uid);
    const diamondRef = orgRef.collection('projects').doc('diamond-restaurant');
    const auditRef = orgRef.collection('auditEvents').doc(crypto.randomUUID());

    await db.runTransaction(async (transaction) => {
      const existing = await transaction.get(orgRef);
      if (existing.exists) {
        const error = new Error('An agency workspace already exists for this account.');
        error.statusCode = 409;
        error.code = 'WORKSPACE_ALREADY_EXISTS';
        throw error;
      }
      const now = fieldValue.serverTimestamp();
      transaction.create(orgRef, {
        name,
        ownerUid: user.uid,
        status: 'active',
        createdAt: now,
        updatedAt: now,
        schemaVersion: 1
      });
      const membership = { organizationId, organizationName: name, role: 'owner', status: 'active', createdAt: now };
      transaction.create(userMembershipRef, membership);
      transaction.create(orgMemberRef, { uid: user.uid, ...membership });
      transaction.create(diamondRef, {
        name: 'Diamond Restaurant',
        nameLower: 'diamond restaurant',
        type: 'Restaurant',
        location: 'BCS Market, New Shimla',
        status: 'active',
        createdBy: user.uid,
        createdAt: now,
        updatedAt: now,
        schemaVersion: 1
      });
      transaction.create(auditRef, {
        actorUid: user.uid,
        action: 'workspace.created',
        resourceType: 'organization',
        resourceId: organizationId,
        createdAt: now
      });
    });

    return json(res, 201, {
      workspace: { id: organizationId, name, role: 'owner' },
      initialProject: { id: 'diamond-restaurant', name: 'Diamond Restaurant' }
    });
  } catch (error) {
    return sendError(res, error);
  }
};
