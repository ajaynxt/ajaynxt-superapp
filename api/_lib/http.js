'use strict';

function secureHeaders(res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
}

function json(res, status, body) {
  secureHeaders(res);
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(body));
}

function methodNotAllowed(res, allowed) {
  res.setHeader('Allow', allowed.join(', '));
  json(res, 405, { error: 'METHOD_NOT_ALLOWED', message: 'This HTTP method is not supported.' });
}

function requestOriginAllowed(req) {
  const configuredOrigin = process.env.APP_ORIGIN;
  const requestOrigin = req.headers && req.headers.origin;
  if (!requestOrigin || !configuredOrigin) return true;
  try {
    return new URL(requestOrigin).origin === new URL(configuredOrigin).origin;
  } catch {
    return false;
  }
}

function badRequest(message, code = 'BAD_REQUEST') {
  const error = new Error(message);
  error.statusCode = 400;
  error.code = code;
  return error;
}

function sendError(res, error) {
  const status = Number.isInteger(error && error.statusCode) ? error.statusCode : 500;
  const known = status >= 400 && status < 500;
  if (status >= 500) {
    // Deliberately do not serialize stack traces, database details, or provider errors.
    console.error('AJAYNXT API error', { code: error && error.code ? String(error.code).slice(0, 80) : 'INTERNAL_ERROR' });
  }
  json(res, status, {
    error: known && error.code ? String(error.code).slice(0, 80) : (known ? 'REQUEST_FAILED' : 'INTERNAL_ERROR'),
    message: known ? String(error.message || 'Request could not be completed.') : 'The server could not complete this request.'
  });
}

function requireAllowedOrigin(req, res) {
  if (requestOriginAllowed(req)) return true;
  json(res, 403, { error: 'ORIGIN_NOT_ALLOWED', message: 'This origin is not allowed.' });
  return false;
}

module.exports = { secureHeaders, json, methodNotAllowed, badRequest, sendError, requireAllowedOrigin };
