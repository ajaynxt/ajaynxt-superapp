import { jwtVerify, createRemoteJWKSet } from 'jose';

const FIREBASE_JWKS = createRemoteJWKSet(new URL('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com'));
const ROLE_READ = new Set(['owner', 'admin', 'operator', 'analyst', 'client_viewer']);
const ROLE_WRITE = new Set(['owner', 'admin', 'operator']);
const ROLE_ADMIN = new Set(['owner', 'admin']);
const REPORT_LIMIT = 2000;
const IMPORT_LIMIT = 80;

class ApiError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}
function json(body, status = 200, extraHeaders = {}) {
  const headers = new Headers(extraHeaders);
  headers.set('Content-Type', 'application/json; charset=utf-8');
  headers.set('Cache-Control', 'no-store, max-age=0');
  headers.set('Pragma', 'no-cache');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Referrer-Policy', 'no-referrer');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  return new Response(JSON.stringify(body), { status, headers });
}
function methodNotAllowed(methods) {
  return json({ error: 'METHOD_NOT_ALLOWED', message: 'This HTTP method is not supported.' }, 405, { Allow: methods.join(', ') });
}
function checkOrigin(request, env) {
  const origin = request.headers.get('Origin');
  if (!origin || !env.APP_ORIGIN) return;
  try {
    if (new URL(origin).origin !== new URL(env.APP_ORIGIN).origin) throw new Error('origin');
  } catch { throw new ApiError(403, 'ORIGIN_NOT_ALLOWED', 'This origin is not allowed.'); }
}
async function parseBody(request, maxBytes = 256 * 1024) {
  const length = Number(request.headers.get('Content-Length') || 0);
  if (length > maxBytes) throw new ApiError(413, 'BODY_TOO_LARGE', 'Request body is too large.');
  const raw = await request.text();
  if (new TextEncoder().encode(raw).length > maxBytes) throw new ApiError(413, 'BODY_TOO_LARGE', 'Request body is too large.');
  let value;
  try { value = JSON.parse(raw); } catch { throw new ApiError(400, 'INVALID_JSON', 'A valid JSON object is required.'); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ApiError(400, 'INVALID_JSON', 'A valid JSON object is required.');
  return value;
}
function clean(value, field, max = 120, required = true) {
  if (typeof value !== 'string') {
    if (!required && (value === undefined || value === null || value === '')) return '';
    throw new ApiError(400, 'INVALID_FIELD', field + ' must be text.');
  }
  const result = value.trim();
  if (required && !result) throw new ApiError(400, 'INVALID_FIELD', field + ' is required.');
  if (result.length > max) throw new ApiError(400, 'INVALID_FIELD', field + ' is too long.');
  return result;
}
function validDate(value) {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) &&
    !Number.isNaN(Date.parse(value + 'T00:00:00.000Z')) &&
    new Date(value + 'T00:00:00.000Z').toISOString().slice(0, 10) === value;
}
function validId(value, field) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(value)) throw new ApiError(400, 'INVALID_ID', 'A valid ' + field + ' is required.');
  return value;
}
async function requireUser(request, env) {
  const match = (request.headers.get('Authorization') || '').match(/^Bearer\s+(.+)$/i);
  if (!match) throw new ApiError(401, 'AUTH_REQUIRED', 'Sign in is required.');
  if (!env.FIREBASE_PROJECT_ID) throw new ApiError(503, 'AUTH_NOT_CONFIGURED', 'Firebase sign-in is not configured yet.');
  let claims;
  try {
    const result = await jwtVerify(match[1], FIREBASE_JWKS, {
      issuer: 'https://securetoken.google.com/' + env.FIREBASE_PROJECT_ID,
      audience: env.FIREBASE_PROJECT_ID,
      algorithms: ['RS256']
    });
    claims = result.payload;
  } catch {
    throw new ApiError(401, 'INVALID_SESSION', 'Session is invalid or expired. Sign in again.');
  }
  if (typeof claims.sub !== 'string' || !claims.sub || claims.sub.length > 128) throw new ApiError(401, 'INVALID_SESSION', 'Session is invalid or expired.');
  return {
    uid: claims.sub,
    email: typeof claims.email === 'string' ? claims.email.toLowerCase() : null,
    emailVerified: claims.email_verified === true,
    name: typeof claims.name === 'string' ? claims.name.slice(0, 120) : null,
    picture: typeof claims.picture === 'string' ? claims.picture.slice(0, 1000) : null
  };
}
function requireSuperAdmin(user, env) {
  if (!env.AJAYNXT_SUPER_ADMIN_UID) throw new ApiError(503, 'SUPER_ADMIN_NOT_CONFIGURED', 'Platform owner setup is incomplete. Configure AJAYNXT_SUPER_ADMIN_UID before onboarding users.');
  if (user.uid !== env.AJAYNXT_SUPER_ADMIN_UID) throw new ApiError(403, 'SUPER_ADMIN_REQUIRED', 'Only the platform Super Admin can perform this action.');
}
async function rememberUser(db, user) {
  await db.prepare("INSERT INTO users (uid, email, email_verified, display_name, photo_url, last_seen_at) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(uid) DO UPDATE SET email=excluded.email, email_verified=excluded.email_verified, display_name=COALESCE(excluded.display_name, users.display_name), photo_url=COALESCE(excluded.photo_url, users.photo_url), last_seen_at=CURRENT_TIMESTAMP")
    .bind(user.uid, user.email, user.emailVerified ? 1 : 0, user.name, user.picture).run();
}
async function audit(db, user, action, type, resourceId, orgId = null, count = null) {
  await db.prepare("INSERT INTO audit_events (id, organization_id, actor_uid, action, resource_type, resource_id, record_count, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)")
    .bind(crypto.randomUUID(), orgId, user.uid, action, type, resourceId || '', count).run();
}
async function orgAccess(db, uid, orgId, allowed = ROLE_READ) {
  validId(orgId, 'organizationId');
  const row = await db.prepare("SELECT o.id, o.name, o.owner_uid, o.status AS org_status, m.role, m.status AS member_status FROM organizations o JOIN org_members m ON m.organization_id=o.id WHERE o.id=? AND m.user_uid=? LIMIT 1")
    .bind(orgId, uid).first();
  if (!row || row.org_status !== 'active' || row.member_status !== 'active') throw new ApiError(404, 'WORKSPACE_NOT_FOUND', 'Workspace was not found or access is not permitted.');
  if (!allowed.has(row.role)) throw new ApiError(403, 'INSUFFICIENT_ROLE', 'You do not have permission to perform this action.');
  return row;
}
async function projectAccess(db, uid, orgId, projectId, allowed = ROLE_READ) {
  const org = await orgAccess(db, uid, orgId, allowed);
  validId(projectId, 'projectId');
  const project = await db.prepare("SELECT id, organization_id, name, type, location, status, created_at, updated_at FROM projects WHERE id=? AND organization_id=? AND status='active' LIMIT 1")
    .bind(projectId, orgId).first();
  if (!project) throw new ApiError(404, 'PROJECT_NOT_FOUND', 'Project was not found or access is not permitted.');
  return { org, project };
}
async function metricRows(db, projectId, start, end, limit) {
  let sql = 'SELECT id, date, platform, platform_key, metric, metric_key, value, source, source_verified, imported_at FROM metrics WHERE project_id=?';
  const args = [projectId];
  if (start) { sql += ' AND date>=?'; args.push(start); }
  if (end) { sql += ' AND date<=?'; args.push(end); }
  sql += ' ORDER BY date DESC, platform ASC, metric ASC LIMIT ?';
  args.push(limit);
  const result = await db.prepare(sql).bind(...args).all();
  return result.results || [];
}
function average(values) { return values.reduce((sum, n) => sum + n, 0) / values.length; }
function consecutive(dates) {
  for (let i = 1; i < dates.length; i++) {
    if (Date.parse(dates[i] + 'T00:00:00Z') - Date.parse(dates[i - 1] + 'T00:00:00Z') !== 86400000) return false;
  }
  return true;
}
function linearForecast(values) {
  const xs = values.map((_, i) => i);
  const mx = average(xs);
  const my = average(values);
  let numerator = 0;
  let denominator = 0;
  xs.forEach((x, i) => { numerator += (x - mx) * (values[i] - my); denominator += (x - mx) * (x - mx); });
  const slope = denominator ? numerator / denominator : 0;
  const intercept = my - slope * mx;
  const dailyEstimates = Array.from({ length: 7 }, (_, i) => Math.max(0, intercept + slope * (values.length + i)));
  return { days: 7, dailyEstimates, averagePerDay: average(dailyEstimates), method: 'Ordinary least-squares trend on 28 consecutive daily values; 7-day point estimate.' };
}
function analyticsFor(records) {
  const map = new Map();
  for (const item of records) {
    const key = item.platform.toLowerCase() + '|||' + item.metric.toLowerCase();
    if (!map.has(key)) map.set(key, { platform: item.platform, metric: item.metric, byDate: new Map() });
    map.get(key).byDate.set(item.date, Number(item.value));
  }
  const coverage = [];
  const comparisons = [];
  const forecasts = [];
  for (const series of map.values()) {
    const dates = Array.from(series.byDate.keys()).sort();
    coverage.push({ platform: series.platform, metric: series.metric, observations: dates.length, firstDate: dates[0] || null, latestDate: dates[dates.length - 1] || null, consecutive14DayWindow: dates.length >= 14 && consecutive(dates.slice(-14)), consecutive28DayWindow: dates.length >= 28 && consecutive(dates.slice(-28)) });
    if (dates.length >= 14) {
      const ds = dates.slice(-14);
      if (consecutive(ds)) {
        const v = ds.map(d => series.byDate.get(d));
        const snapshot = /(followers?|subscribers?|members?_count|total_followers)/i.test(series.metric);
        const prior = snapshot ? v[6] : average(v.slice(0, 7));
        const latest = snapshot ? v[13] : average(v.slice(7, 14));
        comparisons.push({ platform: series.platform, metric: series.metric, comparisonType: snapshot ? 'snapshot_first_window_end_vs_latest_window_end' : 'daily_average_latest_7_vs_previous_7', previousPeriodValue: prior, latestPeriodValue: latest, absoluteChange: latest - prior, percentageChange: prior === 0 ? null : (latest / prior - 1) * 100, startDate: ds[0], previousPeriodEnd: ds[6], latestPeriodStart: ds[7], endDate: ds[13], sourceVerified: false });
      }
    }
    if (dates.length >= 28) {
      const ds = dates.slice(-28);
      if (consecutive(ds)) {
        const v = ds.map(d => series.byDate.get(d));
        const f = linearForecast(v);
        const base = average(v.slice(-7));
        forecasts.push({ platform: series.platform, metric: series.metric, basedOnStartDate: ds[0], basedOnEndDate: ds[27], recent7DayAverage: base, ...f, projectedAverageChangePercent: base === 0 ? null : (f.averagePerDay / base - 1) * 100, sourceVerified: false, disclaimer: 'Estimate only. Does not model seasonality, promotions, stock-outs, ranking changes or uncertainty.' });
      }
    }
  }
  return { coverage, comparisons, forecasts };
}
function metricOut(row) {
  return { id: row.id, date: row.date, platform: row.platform, metric: row.metric, value: Number(row.value), source: row.source || null, sourceVerified: row.source_verified === 1, importedAt: row.imported_at || null };
}
async function router(request, env) {
  checkOrigin(request, env);
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  const db = env.DB;

  if (path === '/api/health') {
    if (method !== 'GET') return methodNotAllowed(['GET']);
    return json({ ok: true, service: 'ajnxt-social-hub-worker', backendConfigured: Boolean(env.DB && env.FIREBASE_PROJECT_ID && env.FIREBASE_API_KEY && env.FIREBASE_AUTH_DOMAIN && env.FIREBASE_APP_ID), ownerAccessConfigured: Boolean(env.AJAYNXT_SUPER_ADMIN_UID), note: 'A healthy API process does not mean social or marketplace accounts are connected.' });
  }

  if (path === '/api/config') {
    if (method !== 'GET') return methodNotAllowed(['GET']);
    const config = { apiKey: env.FIREBASE_API_KEY || '', authDomain: env.FIREBASE_AUTH_DOMAIN || '', projectId: env.FIREBASE_PROJECT_ID || '', appId: env.FIREBASE_APP_ID || '', storageBucket: env.FIREBASE_STORAGE_BUCKET || '', messagingSenderId: env.FIREBASE_MESSAGING_SENDER_ID || '' };
    if (!config.apiKey || !config.authDomain || !config.projectId || !config.appId) return json({ error: 'FIREBASE_WEB_CONFIG_MISSING', message: 'Firebase Web App configuration is not yet set in Cloudflare Worker variables.' }, 503);
    return json({ configured: true, config });
  }

  if (path === '/api/workspaces') {
    const user = await requireUser(request, env);
    if (method === 'GET') {
      await rememberUser(db, user);
      const result = await db.prepare("SELECT o.id, o.name, m.role, o.created_at FROM organizations o JOIN org_members m ON m.organization_id=o.id WHERE m.user_uid=? AND m.status='active' AND o.status='active' ORDER BY o.created_at ASC LIMIT 50")
        .bind(user.uid).all();
      return json({ workspaces: (result.results || []).map(r => ({ id: r.id, name: r.name, role: r.role, createdAt: r.created_at })) });
    }
    if (method !== 'POST') return methodNotAllowed(['GET', 'POST']);
    requireSuperAdmin(user, env);
    const body = await parseBody(request, 16384);
    const name = clean(body.name || 'AJAYNXT Workspace', 'Workspace name', 100);
    const existing = await db.prepare('SELECT id FROM organizations WHERE owner_uid=? LIMIT 1').bind(user.uid).first();
    if (existing) throw new ApiError(409, 'WORKSPACE_ALREADY_EXISTS', 'Your agency workspace already exists.');
    const orgId = 'org_' + crypto.randomUUID().replaceAll('-', '');
    const auditId = crypto.randomUUID();
    await db.batch([
      db.prepare("INSERT INTO organizations (id,name,owner_uid,status,created_at,updated_at,schema_version) VALUES (?,?,?,'active',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,1)").bind(orgId, name, user.uid),
      db.prepare("INSERT INTO org_members (organization_id,user_uid,role,status,created_by,created_at) VALUES (?,?,'owner','active',?,CURRENT_TIMESTAMP)").bind(orgId, user.uid, user.uid),
      db.prepare("INSERT INTO projects (id,organization_id,name,name_lower,type,location,status,created_by,created_at,updated_at,schema_version) VALUES (? ,?,'Diamond Restaurant','diamond restaurant','Restaurant','BCS Market, New Shimla','active',?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,1)").bind('diamond-restaurant', orgId, user.uid),
      db.prepare("INSERT INTO audit_events (id,organization_id,actor_uid,action,resource_type,resource_id,created_at) VALUES (?,?,?,'workspace.created','organization',?,CURRENT_TIMESTAMP)").bind(auditId, orgId, user.uid, orgId)
    ]);
    return json({ workspace: { id: orgId, name, role: 'owner' }, initialProject: { id: 'diamond-restaurant', name: 'Diamond Restaurant' } }, 201);
  }

  if (path === '/api/projects') {
    const user = await requireUser(request, env);
    const orgId = url.searchParams.get('organizationId');
    if (!orgId) throw new ApiError(400, 'ORGANIZATION_ID_REQUIRED', 'organizationId is required.');
    if (method === 'GET') {
      await orgAccess(db, user.uid, orgId);
      const result = await db.prepare("SELECT id,name,type,location,status,created_at FROM projects WHERE organization_id=? AND status='active' ORDER BY created_at ASC LIMIT 200").bind(orgId).all();
      return json({ projects: (result.results || []).map(p => ({ id: p.id, name: p.name, type: p.type, location: p.location || '', status: p.status, createdAt: p.created_at })) });
    }
    if (method !== 'POST') return methodNotAllowed(['GET', 'POST']);
    await orgAccess(db, user.uid, orgId, ROLE_ADMIN);
    const body = await parseBody(request, 16384);
    const name = clean(body.name, 'Project name', 90);
    const type = clean(body.type || 'Other', 'Project type', 60);
    const location = clean(body.location || '', 'Project location', 120, false);
    const duplicate = await db.prepare("SELECT id FROM projects WHERE organization_id=? AND name_lower=? AND status='active' LIMIT 1").bind(orgId, name.toLowerCase()).first();
    if (duplicate) throw new ApiError(409, 'PROJECT_NAME_EXISTS', 'A project with this name already exists.');
    const id = crypto.randomUUID();
    await db.batch([
      db.prepare("INSERT INTO projects (id,organization_id,name,name_lower,type,location,status,created_by,created_at,updated_at,schema_version) VALUES (?,?,?,?,?,?,'active',?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,1)").bind(id, orgId, name, name.toLowerCase(), type, location, user.uid),
      db.prepare("INSERT INTO audit_events (id,organization_id,actor_uid,action,resource_type,resource_id,created_at) VALUES (?,?,?,'project.created','project',?,CURRENT_TIMESTAMP)").bind(crypto.randomUUID(), orgId, user.uid, id)
    ]);
    return json({ project: { id, name, type, location, status: 'active', createdAt: new Date().toISOString() } }, 201);
  }

  const detail = path.match(/^\/api\/projects\/([A-Za-z0-9_-]+)$/);
  if (detail) {
    const user = await requireUser(request, env);
    const projectId = detail[1];
    const orgId = url.searchParams.get('organizationId');
    if (!orgId) throw new ApiError(400, 'ORGANIZATION_ID_REQUIRED', 'organizationId is required.');
    const access = await projectAccess(db, user.uid, orgId, projectId, ROLE_ADMIN);
    if (method === 'PATCH') {
      const body = await parseBody(request, 16384);
      const name = clean(body.name, 'Project name', 90);
      const type = clean(body.type || access.project.type || 'Other', 'Project type', 60);
      const location = clean(body.location === undefined ? (access.project.location || '') : body.location, 'Project location', 120, false);
      const duplicate = await db.prepare("SELECT id FROM projects WHERE organization_id=? AND name_lower=? AND status='active' AND id<>? LIMIT 1").bind(orgId, name.toLowerCase(), projectId).first();
      if (duplicate) throw new ApiError(409, 'PROJECT_NAME_EXISTS', 'A project with this name already exists.');
      await db.batch([
        db.prepare("UPDATE projects SET name=?,name_lower=?,type=?,location=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND organization_id=?").bind(name, name.toLowerCase(), type, location, projectId, orgId),
        db.prepare("INSERT INTO audit_events (id,organization_id,actor_uid,action,resource_type,resource_id,created_at) VALUES (?,?,?,'project.updated','project',?,CURRENT_TIMESTAMP)").bind(crypto.randomUUID(), orgId, user.uid, projectId)
      ]);
      return json({ project: { id: projectId, name, type, location, status: 'active' } });
    }
    if (method === 'DELETE') {
      await db.batch([
        db.prepare("UPDATE projects SET status='archived',updated_at=CURRENT_TIMESTAMP WHERE id=? AND organization_id=? AND status='active'").bind(projectId, orgId),
        db.prepare("INSERT INTO audit_events (id,organization_id,actor_uid,action,resource_type,resource_id,created_at) VALUES (?,?,?,'project.archived','project',?,CURRENT_TIMESTAMP)").bind(crypto.randomUUID(), orgId, user.uid, projectId)
      ]);
      return json({ archived: true, projectId });
    }
    return methodNotAllowed(['PATCH', 'DELETE']);
  }

  const metricRoute = path.match(/^\/api\/projects\/([A-Za-z0-9_-]+)\/(metrics|imports|reports)$/);
  if (metricRoute) {
    const user = await requireUser(request, env);
    const projectId = metricRoute[1];
    const mode = metricRoute[2];
    const orgId = url.searchParams.get('organizationId');
    if (!orgId) throw new ApiError(400, 'ORGANIZATION_ID_REQUIRED', 'organizationId is required.');
    const access = await projectAccess(db, user.uid, orgId, projectId, mode === 'imports' ? ROLE_WRITE : ROLE_READ);

    if (mode === 'metrics') {
      if (method !== 'GET') return methodNotAllowed(['GET']);
      const start = url.searchParams.get('startDate');
      const end = url.searchParams.get('endDate');
      if (start && !validDate(start)) throw new ApiError(400, 'INVALID_START_DATE', 'startDate must use YYYY-MM-DD format.');
      if (end && !validDate(end)) throw new ApiError(400, 'INVALID_END_DATE', 'endDate must use YYYY-MM-DD format.');
      if (start && end && start > end) throw new ApiError(400, 'INVALID_DATE_RANGE', 'startDate must be on or before endDate.');
      let limit = Number.parseInt(url.searchParams.get('limit') || '500', 10);
      if (!Number.isFinite(limit) || limit < 1) limit = 500;
      limit = Math.min(limit, 1000);
      const rows = await metricRows(db, projectId, start, end, limit);
      return json({ organizationId: orgId, projectId, projectName: access.project.name, count: rows.length, metrics: rows.map(metricOut), note: 'Values are only as verified as their provider/API or import source.' });
    }

    if (mode === 'imports') {
      if (method !== 'POST') return methodNotAllowed(['POST']);
      const body = await parseBody(request, 256 * 1024);
      if (body.organizationId !== orgId) throw new ApiError(400, 'ORGANIZATION_SCOPE_MISMATCH', 'Request organization scope does not match the URL.');
      if (!Array.isArray(body.records) || body.records.length < 1 || body.records.length > IMPORT_LIMIT) throw new ApiError(400, 'INVALID_RECORD_COUNT', 'Import between 1 and ' + IMPORT_LIMIT + ' observations per request.');
      const records = body.records.map((item, i) => {
        if (!item || typeof item !== 'object' || Array.isArray(item)) throw new ApiError(400, 'INVALID_RECORD', 'Record ' + (i + 1) + ' must be an object.');
        if (!validDate(item.date)) throw new ApiError(400, 'INVALID_DATE', 'Record ' + (i + 1) + ' has an invalid date.');
        const platform = clean(item.platform, 'platform', 60);
        const metric = clean(item.metric, 'metric', 64).toLowerCase().replace(/\s+/g, '_');
        if (!/^[a-z][a-z0-9_]{0,63}$/.test(metric)) throw new ApiError(400, 'INVALID_METRIC', 'Metric names must start with a letter and contain lowercase letters, digits or underscores.');
        const value = typeof item.value === 'number' ? item.value : Number(item.value);
        if (!Number.isFinite(value) || value < 0 || value > 1e15) throw new ApiError(400, 'INVALID_METRIC_VALUE', 'Metric values must be finite, non-negative numbers no greater than 1e15.');
        const source = clean(item.source || 'User CSV import', 'source', 160);
        return { date: item.date, platform, platformKey: platform.toLowerCase(), metric, metricKey: metric.toLowerCase(), value, source };
      });
      const seen = new Set();
      for (const r of records) {
        const key = r.date + '|' + r.platformKey + '|' + r.metricKey;
        if (seen.has(key)) throw new ApiError(409, 'DUPLICATE_INPUT_RECORD', 'Import contains duplicate date/platform/metric observations.');
        seen.add(key);
      }
      const minDate = records.reduce((m, r) => r.date < m ? r.date : m, records[0].date);
      const maxDate = records.reduce((m, r) => r.date > m ? r.date : m, records[0].date);
      const stored = await db.prepare('SELECT date,platform_key,metric_key FROM metrics WHERE project_id=? AND date>=? AND date<=? LIMIT 10000').bind(projectId, minDate, maxDate).all();
      const known = new Set((stored.results || []).map(r => r.date + '|' + r.platform_key + '|' + r.metric_key));
      for (const r of records) if (known.has(r.date + '|' + r.platformKey + '|' + r.metricKey)) throw new ApiError(409, 'DUPLICATE_STORED_RECORD', 'One or more observations already exist. Duplicate records are not overwritten.');
      const statements = records.map(async (r) => {
        const input = new TextEncoder().encode([projectId, r.date, r.platformKey, r.metricKey].join('|'));
        const digest = await crypto.subtle.digest('SHA-256', input);
        const id = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
        return db.prepare('INSERT INTO metrics (id,organization_id,project_id,date,platform,platform_key,metric,metric_key,value,source,source_verified,imported_by,imported_at) VALUES (?,?,?,?,?,?,?,?,?,?,0,?,CURRENT_TIMESTAMP)')
          .bind(id, orgId, projectId, r.date, r.platform, r.platformKey, r.metric, r.metricKey, r.value, r.source, user.uid);
      });
      const prepared = await Promise.all(statements);
      prepared.push(db.prepare("INSERT INTO audit_events (id,organization_id,actor_uid,action,resource_type,resource_id,record_count,created_at) VALUES (?,?,?,'metrics.imported','project',?,?,CURRENT_TIMESTAMP)").bind(crypto.randomUUID(), orgId, user.uid, projectId, records.length));
      try { await db.batch(prepared); } catch { throw new ApiError(409, 'IMPORT_CONFLICT', 'The import conflicted with a stored observation. Review duplicates and try again.'); }
      return json({ imported: records.length, projectId, organizationId: orgId, sourceVerified: false, message: 'Imported. Source is not independently verified; missing dates are not treated as zero.' }, 201);
    }

    if (mode === 'reports') {
      if (method !== 'GET') return methodNotAllowed(['GET']);
      const start = url.searchParams.get('startDate');
      const end = url.searchParams.get('endDate');
      if (start && !validDate(start)) throw new ApiError(400, 'INVALID_START_DATE', 'startDate must use YYYY-MM-DD format.');
      if (end && !validDate(end)) throw new ApiError(400, 'INVALID_END_DATE', 'endDate must use YYYY-MM-DD format.');
      if (start && end && start > end) throw new ApiError(400, 'INVALID_DATE_RANGE', 'startDate must be on or before endDate.');
      let limit = Number.parseInt(url.searchParams.get('limit') || String(REPORT_LIMIT), 10);
      if (!Number.isFinite(limit) || limit < 1) limit = REPORT_LIMIT;
      limit = Math.min(limit, REPORT_LIMIT);
      const rows = await metricRows(db, projectId, start, end, limit);
      const ordered = rows.slice().reverse();
      const analytics = analyticsFor(ordered);
      const first = rows.length ? rows.reduce((m, r) => r.date < m ? r.date : m, rows[0].date) : null;
      const latest = rows.length ? rows.reduce((m, r) => r.date > m ? r.date : m, rows[0].date) : null;
      return json({
        project: { id: projectId, name: access.project.name }, organizationId: orgId, generatedAt: new Date().toISOString(),
        recordCount: rows.length, dataCoverage: { firstDate: first, latestDate: latest, limitApplied: rows.length === limit },
        ...analytics, records: rows.map(metricOut),
        disclaimers: ['Imported records have not been independently verified against provider systems.', 'Missing dates are not zero; comparisons require complete consecutive windows.', 'Trend estimates are not promises and do not prove causation.', 'Revenue is not profit without validated costs.']
      });
    }
  }

  if (path === '/api/admin/admins') {
    const user = await requireUser(request, env);
    requireSuperAdmin(user, env);
    if (method === 'GET') {
      const rows = await db.prepare('SELECT uid,admin_id,email,display_name,status,created_at,revoked_at FROM platform_admins ORDER BY created_at DESC LIMIT 500').all();
      return json({ superAdmin: { uid: user.uid, email: user.email }, admins: rows.results || [], rule: 'Only the configured Super Admin UID can create/revoke platform Admin IDs.' });
    }
    if (method === 'POST') {
      const body = await parseBody(request, 16384);
      const email = clean(body.email, 'Admin email', 254).toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new ApiError(400, 'INVALID_EMAIL', 'Enter a valid email address.');
      if (email === user.email) throw new ApiError(400, 'CANNOT_PROMOTE_OWNER', 'The Super Admin must not be created as a regular Admin ID.');
      const target = await db.prepare('SELECT uid,email,display_name FROM users WHERE email=? LIMIT 1').bind(email).first();
      if (!target) throw new ApiError(404, 'USER_NOT_REGISTERED', 'This person must sign into AJAYNXT Social Hub once before you can create their Admin ID.');
      const old = await db.prepare('SELECT uid,admin_id,status FROM platform_admins WHERE uid=? LIMIT 1').bind(target.uid).first();
      if (old && old.status === 'active') throw new ApiError(409, 'ADMIN_ALREADY_EXISTS', 'This user already has an active Admin ID.');
      const adminId = old ? old.admin_id : 'AJN-ADM-' + crypto.randomUUID().replaceAll('-', '').slice(0, 8).toUpperCase();
      if (old) {
        await db.prepare("UPDATE platform_admins SET status='active',revoked_at=NULL WHERE uid=?").bind(target.uid).run();
      } else {
        await db.prepare("INSERT INTO platform_admins (uid,admin_id,email,display_name,status,created_by,created_at) VALUES (?,?,?,?,'active',?,CURRENT_TIMESTAMP)").bind(target.uid, adminId, email, target.display_name || '', user.uid).run();
      }
      await audit(db, user, 'admin.created', 'platform_admin', target.uid);
      return json({ created: true, admin: { uid: target.uid, adminId, email, displayName: target.display_name || '', status: 'active' }, message: 'Admin access created. Only Super Admin can create/revoke Admin IDs.' }, 201);
    }
    if (method === 'DELETE') {
      const uid = url.searchParams.get('uid');
      if (!uid || uid === user.uid) throw new ApiError(400, 'INVALID_ADMIN_UID', 'A different Admin UID is required.');
      const target = await db.prepare('SELECT uid,admin_id,status FROM platform_admins WHERE uid=? LIMIT 1').bind(uid).first();
      if (!target || target.status !== 'active') throw new ApiError(404, 'ADMIN_NOT_FOUND', 'Active Admin ID was not found.');
      await db.prepare("UPDATE platform_admins SET status='revoked',revoked_at=CURRENT_TIMESTAMP WHERE uid=?").bind(uid).run();
      await audit(db, user, 'admin.revoked', 'platform_admin', uid);
      return json({ revoked: true, uid, adminId: target.admin_id });
    }
    return methodNotAllowed(['GET', 'POST', 'DELETE']);
  }

  if (path === '/api/admin/members') {
    const user = await requireUser(request, env);
    requireSuperAdmin(user, env);
    const orgId = url.searchParams.get('organizationId');
    if (!orgId) throw new ApiError(400, 'ORGANIZATION_ID_REQUIRED', 'organizationId is required.');
    await orgAccess(db, user.uid, orgId, ROLE_ADMIN);
    if (method === 'GET') {
      const rows = await db.prepare('SELECT m.user_uid AS uid,u.email,u.display_name,m.role,m.status,m.created_at FROM org_members m LEFT JOIN users u ON u.uid=m.user_uid WHERE m.organization_id=? ORDER BY m.created_at ASC LIMIT 500').bind(orgId).all();
      return json({ members: rows.results || [] });
    }
    if (method === 'POST') {
      const body = await parseBody(request, 16384);
      const email = clean(body.email, 'Member email', 254).toLowerCase();
      const role = clean(body.role, 'Role', 40);
      if (!['operator', 'analyst', 'client_viewer', 'admin'].includes(role)) throw new ApiError(400, 'INVALID_ROLE', 'Choose operator, analyst, client_viewer, or a previously created platform admin.');
      const target = await db.prepare('SELECT uid,email,display_name FROM users WHERE email=? LIMIT 1').bind(email).first();
      if (!target) throw new ApiError(404, 'USER_NOT_REGISTERED', 'This person must sign into AJAYNXT Social Hub once before they can be added to a workspace.');
      if (target.uid === user.uid) throw new ApiError(400, 'SELF_MEMBERSHIP', 'The Super Admin is already the workspace owner.');
      if (role === 'admin') {
        const activeAdmin = await db.prepare("SELECT uid FROM platform_admins WHERE uid=? AND status='active' LIMIT 1").bind(target.uid).first();
        if (!activeAdmin) throw new ApiError(403, 'PLATFORM_ADMIN_REQUIRED', 'Create this person’s platform Admin ID first. Only the Super Admin can do that.');
      }
      const prior = await db.prepare('SELECT role,status FROM org_members WHERE organization_id=? AND user_uid=? LIMIT 1').bind(orgId, target.uid).first();
      if (prior && prior.status === 'active') throw new ApiError(409, 'MEMBER_ALREADY_EXISTS', 'This person is already a member of this workspace.');
      await db.prepare("INSERT INTO org_members (organization_id,user_uid,role,status,created_by,created_at) VALUES (?,?,?,'active',?,CURRENT_TIMESTAMP) ON CONFLICT(organization_id,user_uid) DO UPDATE SET role=excluded.role,status='active',created_by=excluded.created_by").bind(orgId, target.uid, role, user.uid).run();
      await audit(db, user, 'workspace.member_added', 'workspace_member', target.uid, orgId);
      return json({ added: true, member: { uid: target.uid, email, displayName: target.display_name || '', role, status: 'active' } }, 201);
    }
    if (method === 'DELETE') {
      const uid = url.searchParams.get('uid');
      if (!uid) throw new ApiError(400, 'MEMBER_UID_REQUIRED', 'uid is required.');
      const member = await db.prepare('SELECT role FROM org_members WHERE organization_id=? AND user_uid=? LIMIT 1').bind(orgId, uid).first();
      if (!member) throw new ApiError(404, 'MEMBER_NOT_FOUND', 'Workspace member was not found.');
      if (member.role === 'owner' || uid === user.uid) throw new ApiError(403, 'OWNER_PROTECTED', 'The workspace owner cannot be removed here.');
      await db.prepare("UPDATE org_members SET status='revoked' WHERE organization_id=? AND user_uid=?").bind(orgId, uid).run();
      await audit(db, user, 'workspace.member_revoked', 'workspace_member', uid, orgId);
      return json({ revoked: true, uid });
    }
    return methodNotAllowed(['GET', 'POST', 'DELETE']);
  }

  return json({ error: 'NOT_FOUND', message: 'Endpoint not found.' }, 404);
}

export default {
  async fetch(request, env) {
    if (!new URL(request.url).pathname.startsWith('/api/')) {
      if (env.ASSETS) return env.ASSETS.fetch(request);
      return new Response('AJAYNXT Social Hub assets are not configured.', { status: 503 });
    }
    try {
      return await router(request, env);
    } catch (error) {
      if (error instanceof ApiError) return json({ error: error.code, message: error.message }, error.status);
      console.error('AJAYNXT API failure', { type: error && error.name ? String(error.name).slice(0, 64) : 'Error' });
      return json({ error: 'INTERNAL_ERROR', message: 'The server could not complete this request.' }, 500);
    }
  }
};
export { analyticsFor, validDate, requireSuperAdmin };
