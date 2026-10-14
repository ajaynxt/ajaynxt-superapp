'use strict';

const { json, methodNotAllowed, requireAllowedOrigin } = require('./_lib/http');

module.exports = async function health(req, res) {
  if (req.method !== 'GET') return methodNotAllowed(res, ['GET']);
  if (!requireAllowedOrigin(req, res)) return;
  return json(res, 200, {
    ok: true,
    service: 'ajnxt-social-hub-api',
    backendConfigured: Boolean(process.env.FIREBASE_SERVICE_ACCOUNT_JSON),
    note: 'A healthy API process does not mean external social/platform accounts are connected.'
  });
};
