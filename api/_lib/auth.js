'use strict';

const { getFirebaseAdmin } = require('./firebase');

async function requireUser(req) {
  const header = req.headers && req.headers.authorization;
  const match = typeof header === 'string' ? header.match(/^Bearer\s+(.+)$/i) : null;
  if (!match) {
    const error = new Error('Sign-in is required.');
    error.statusCode = 401;
    error.code = 'AUTH_REQUIRED';
    throw error;
  }

  const { auth } = getFirebaseAdmin();
  try {
    const decoded = await auth.verifyIdToken(match[1], true);
    return {
      uid: decoded.uid,
      email: typeof decoded.email === 'string' ? decoded.email : null,
      emailVerified: decoded.email_verified === true
    };
  } catch {
    const error = new Error('Session is invalid or expired. Sign in again.');
    error.statusCode = 401;
    error.code = 'INVALID_SESSION';
    throw error;
  }
}

module.exports = { requireUser };
