'use strict';

const { json, methodNotAllowed, requireAllowedOrigin } = require('./_lib/http');

module.exports = async function publicConfig(req, res) {
  if (req.method !== 'GET') return methodNotAllowed(res, ['GET']);
  if (!requireAllowedOrigin(req, res)) return;

  const config = {
    apiKey: process.env.FIREBASE_API_KEY || '',
    authDomain: process.env.FIREBASE_AUTH_DOMAIN || '',
    projectId: process.env.FIREBASE_PROJECT_ID || '',
    appId: process.env.FIREBASE_APP_ID || '',
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET || '',
    messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID || ''
  };
  const required = ['apiKey', 'authDomain', 'projectId', 'appId'];
  const missing = required.filter((key) => !config[key]);
  if (missing.length) {
    return json(res, 503, {
      error: 'FIREBASE_WEB_CONFIG_MISSING',
      message: 'Firebase Web App configuration is not yet set in the deployment environment.'
    });
  }

  return json(res, 200, { configured: true, config });
};
