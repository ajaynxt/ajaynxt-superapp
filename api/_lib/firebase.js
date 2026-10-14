'use strict';

const { getApps, initializeApp, cert } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');

const APP_NAME = 'ajnxt-social-hub-api';

function getFirebaseAdmin() {
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (!raw) {
    const error = new Error('Firebase server credentials are not configured.');
    error.statusCode = 503;
    error.code = 'FIREBASE_NOT_CONFIGURED';
    throw error;
  }

  let serviceAccount;
  try {
    serviceAccount = JSON.parse(raw);
  } catch {
    const error = new Error('Firebase server configuration is invalid.');
    error.statusCode = 503;
    error.code = 'FIREBASE_CONFIG_INVALID';
    throw error;
  }

  if (!serviceAccount.project_id || !serviceAccount.client_email || !serviceAccount.private_key) {
    const error = new Error('Firebase server configuration is incomplete.');
    error.statusCode = 503;
    error.code = 'FIREBASE_CONFIG_INCOMPLETE';
    throw error;
  }

  let app = getApps().find((item) => item.name === APP_NAME);
  if (!app) {
    const privateKey = String(serviceAccount.private_key).replace(/\\n/g, '\n');
    app = initializeApp({
      credential: cert({ ...serviceAccount, private_key: privateKey }),
      projectId: serviceAccount.project_id
    }, APP_NAME);
  }

  return {
    auth: getAuth(app),
    db: getFirestore(app),
    fieldValue: FieldValue,
    projectId: serviceAccount.project_id
  };
}

module.exports = { getFirebaseAdmin };
