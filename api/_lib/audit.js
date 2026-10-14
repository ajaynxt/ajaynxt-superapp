'use strict';

async function writeAudit(db, fieldValue, details) {
  const ref = db.collection('organizations').doc(details.organizationId).collection('auditEvents').doc();
  const safeDetails = {
    actorUid: details.actorUid,
    action: details.action,
    resourceType: details.resourceType,
    resourceId: details.resourceId,
    createdAt: fieldValue.serverTimestamp()
  };
  await ref.set(safeDetails);
}

module.exports = { writeAudit };
