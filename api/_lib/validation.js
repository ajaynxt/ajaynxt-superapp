'use strict';

function parseJsonBody(req, maxBytes = 256 * 1024) {
  const body = req.body;
  if (typeof body === 'string') {
    if (Buffer.byteLength(body, 'utf8') > maxBytes) {
      const error = new Error('Request body is too large.');
      error.statusCode = 413;
      error.code = 'BODY_TOO_LARGE';
      throw error;
    }
    try {
      const parsed = JSON.parse(body);
      if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') throw new Error('not-object');
      return parsed;
    } catch {
      const error = new Error('A valid JSON object is required.');
      error.statusCode = 400;
      error.code = 'INVALID_JSON';
      throw error;
    }
  }
  if (!body || Array.isArray(body) || typeof body !== 'object') {
    const error = new Error('A valid JSON object is required.');
    error.statusCode = 400;
    error.code = 'INVALID_JSON';
    throw error;
  }
  if (Buffer.byteLength(JSON.stringify(body), 'utf8') > maxBytes) {
    const error = new Error('Request body is too large.');
    error.statusCode = 413;
    error.code = 'BODY_TOO_LARGE';
    throw error;
  }
  return body;
}

function cleanString(value, label, maxLength, required = true) {
  if (typeof value !== 'string') {
    if (!required && (value === undefined || value === null || value === '')) return '';
    const error = new Error(label + ' must be text.');
    error.statusCode = 400;
    error.code = 'INVALID_FIELD';
    throw error;
  }
  const clean = value.trim();
  if (required && !clean) {
    const error = new Error(label + ' is required.');
    error.statusCode = 400;
    error.code = 'INVALID_FIELD';
    throw error;
  }
  if (clean.length > maxLength) {
    const error = new Error(label + ' is too long.');
    error.statusCode = 400;
    error.code = 'INVALID_FIELD';
    throw error;
  }
  return clean;
}

function validIsoDate(value) {
  return typeof value === 'string'
    && /^\d{4}-\d{2}-\d{2}$/.test(value)
    && !Number.isNaN(Date.parse(value + 'T00:00:00.000Z'))
    && new Date(value + 'T00:00:00.000Z').toISOString().slice(0, 10) === value;
}

module.exports = { parseJsonBody, cleanString, validIsoDate };
