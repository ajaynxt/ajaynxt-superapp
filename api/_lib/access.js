'use strict';

const { badRequest } = require('./http');

const VALID_ROLES = new Set(['owner', 'admin', 'operator', 'analyst', 'client_viewer']);
const READ_ROLES = new Set(['owner', 'admin', 'operator', 'analyst', 'client_viewer']);
const WRITE_ROLES = new Set(['owner', 'admin', 'operator']);
const ADMIN_ROLES = new Set(['owner', 'admin']);

function requireDocumentId(value, label) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(value)) {
    throw badRequest('A valid ' + label + ' is required.');
  }
  return value;
}

async function requireOrganization(db, uid, organizationId, allowedRoles = READ_ROLES) {
  requireDocumentId(organizationId, 'organizationId');
  const [organization, membership] = await Promise.all([
    db.collection('organizations').doc(organizationId).get(),
    db.collection('users').doc(uid).collection('organizations').doc(organizationId).get()
  ]);

  if (!organization.exists || !membership.exists) {
    const error = new Error('Workspace was not found or access is not permitted.');
    error.statusCode = 404;
    error.code = 'WORKSPACE_NOT_FOUND';
    throw error;
  }

  const member = membership.data();
  const role = member.role;
  if (member.status !== 'active' || !VALID_ROLES.has(role) || !allowedRoles.has(role)) {
    const error = new Error('You do not have permission to perform this action.');
    error.statusCode = 403;
    error.code = 'INSUFFICIENT_ROLE';
    throw error;
  }

  return { organizationId, organization: organization.data(), role, membership: member };
}

async function requireProject(db, uid, organizationId, projectId, allowedRoles = READ_ROLES) {
  const workspace = await requireOrganization(db, uid, organizationId, allowedRoles);
  requireDocumentId(projectId, 'projectId');
  const projectRef = db.collection('organizations').doc(organizationId).collection('projects').doc(projectId);
  const project = await projectRef.get();

  if (!project.exists || project.data().status === 'archived') {
    const error = new Error('Project was not found or access is not permitted.');
    error.statusCode = 404;
    error.code = 'PROJECT_NOT_FOUND';
    throw error;
  }

  return { ...workspace, projectId, project: project.data(), projectRef };
}

module.exports = { VALID_ROLES, READ_ROLES, WRITE_ROLES, ADMIN_ROLES, requireDocumentId, requireOrganization, requireProject };
