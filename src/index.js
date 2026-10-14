import { jwtVerify, createRemoteJWKSet } from 'jose';

const GOOGLE_KEYS = createRemoteJWKSet(new URL('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com'));
const READ = new Set(['owner','admin','operator','analyst','client_viewer']);
const WRITE = new Set(['owner','admin','operator']);
const ADMIN = new Set(['owner','admin']);
const RETENTION_DAYS = 365;
const RETENTION_BATCH_SIZE = 250;
const RETENTION_BATCHES_PER_TABLE = 20;

class ApiError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}
function reply(data, status = 200, extra = {}) {
  const headers = new Headers(extra);
  headers.set('Content-Type','application/json; charset=utf-8');
  headers.set('Cache-Control','no-store, max-age=0');
  headers.set('Pragma','no-cache');
  headers.set('X-Content-Type-Options','nosniff');
  headers.set('Referrer-Policy','no-referrer');
  headers.set('X-Frame-Options','DENY');
  headers.set('Permissions-Policy','camera=(), microphone=(), geolocation=()');
  return new Response(JSON.stringify(data),{status,headers});
}
function methodDenied(methods) { return reply({error:'METHOD_NOT_ALLOWED',message:'This HTTP method is not supported.'},405,{Allow:methods.join(', ')}); }
function fail(status,code,message) { throw new ApiError(status,code,message); }
function checkOrigin(request,env) {
  const origin=request.headers.get('Origin');
  if(!origin||!env.APP_ORIGIN)return;
  try { if(new URL(origin).origin!==new URL(env.APP_ORIGIN).origin)fail(403,'ORIGIN_NOT_ALLOWED','This origin is not allowed.'); }
  catch(e) { if(e instanceof ApiError)throw e; fail(403,'ORIGIN_NOT_ALLOWED','This origin is not allowed.'); }
}
async function bodyJson(request,maxBytes=262144) {
  const length=Number(request.headers.get('Content-Length')||0);
  if(length>maxBytes)fail(413,'BODY_TOO_LARGE','Request body is too large.');
  const raw=await request.text();
  if(new TextEncoder().encode(raw).length>maxBytes)fail(413,'BODY_TOO_LARGE','Request body is too large.');
  let data;try{data=JSON.parse(raw);}catch{fail(400,'INVALID_JSON','A valid JSON object is required.');}
  if(!data||typeof data!=='object'||Array.isArray(data))fail(400,'INVALID_JSON','A valid JSON object is required.');
  return data;
}
function textValue(value,label,max=120,required=true) {
  if(typeof value!=='string'){if(!required&&(value===null||value===undefined||value===''))return '';fail(400,'INVALID_FIELD',label+' must be text.');}
  const clean=value.trim();
  if(required&&!clean)fail(400,'INVALID_FIELD',label+' is required.');
  if(clean.length>max)fail(400,'INVALID_FIELD',label+' is too long.');
  return clean;
}
function validDate(value) {
  return typeof value==='string'&&/^\d{4}-\d{2}-\d{2}$/.test(value)&&!Number.isNaN(Date.parse(value+'T00:00:00.000Z'))&&new Date(value+'T00:00:00.000Z').toISOString().slice(0,10)===value;
}
function idValue(value,label) { if(typeof value!=='string'||!/^[A-Za-z0-9_-]{1,128}$/.test(value))fail(400,'INVALID_ID','A valid '+label+' is required.');return value; }
function dateRange(query) {
  const start=query.get('startDate'),end=query.get('endDate');
  if(start&&!validDate(start))fail(400,'INVALID_START_DATE','startDate must use YYYY-MM-DD.');
  if(end&&!validDate(end))fail(400,'INVALID_END_DATE','endDate must use YYYY-MM-DD.');
  if(start&&end&&start>end)fail(400,'INVALID_DATE_RANGE','startDate must be on or before endDate.');
  return {start:start||null,end:end||null};
}
async function requireUser(request,env) {
  const match=(request.headers.get('Authorization')||'').match(/^Bearer\s+(.+)$/i);
  if(!match)fail(401,'AUTH_REQUIRED','Sign in is required.');
  if(!env.FIREBASE_PROJECT_ID)fail(503,'AUTH_NOT_CONFIGURED','Firebase Google sign-in is not configured.');
  let claims;
  try {
    const verified=await jwtVerify(match[1],GOOGLE_KEYS,{issuer:'https://securetoken.google.com/'+env.FIREBASE_PROJECT_ID,audience:env.FIREBASE_PROJECT_ID,algorithms:['RS256']});
    claims=verified.payload;
  } catch { fail(401,'INVALID_SESSION','Session is invalid or expired. Sign in again.'); }
  if(typeof claims.sub!=='string'||!claims.sub||claims.sub.length>128)fail(401,'INVALID_SESSION','Session is invalid or expired.');
  return {uid:claims.sub,email:typeof claims.email==='string'?claims.email.toLowerCase():null,emailVerified:claims.email_verified===true,name:typeof claims.name==='string'?claims.name.slice(0,120):null,picture:typeof claims.picture==='string'?claims.picture.slice(0,1000):null};
}
function requireOwner(user,env) {
  if(!env.AJAYNXT_SUPER_ADMIN_UID)fail(503,'SUPER_ADMIN_NOT_CONFIGURED','Configure the AJAYNXT_SUPER_ADMIN_UID Worker secret before onboarding workspaces.');
  if(user.uid!==env.AJAYNXT_SUPER_ADMIN_UID)fail(403,'SUPER_ADMIN_REQUIRED','Only the platform Super Admin can perform this action.');
}
async function rememberUser(db,user) {
  await db.prepare("INSERT INTO users(uid,email,email_verified,display_name,photo_url,last_seen_at) VALUES(?,?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(uid) DO UPDATE SET email=excluded.email,email_verified=excluded.email_verified,display_name=COALESCE(excluded.display_name,users.display_name),photo_url=COALESCE(excluded.photo_url,users.photo_url),last_seen_at=CURRENT_TIMESTAMP")
    .bind(user.uid,user.email,user.emailVerified?1:0,user.name,user.picture).run();
}
async function audit(db,user,action,type,resourceId,orgId=null,count=null) {
  await db.prepare("INSERT INTO audit_events(id,organization_id,actor_uid,action,resource_type,resource_id,record_count,created_at) VALUES(?,?,?,?,?,?,?,CURRENT_TIMESTAMP)")
    .bind(crypto.randomUUID(),orgId,user.uid,action,type,resourceId||'',count).run();
}
async function orgAccess(db,uid,orgId,roles=READ) {
  idValue(orgId,'organizationId');
  const row=await db.prepare("SELECT o.id,o.name,o.owner_uid,o.status org_status,m.role,m.status member_status FROM organizations o JOIN org_members m ON m.organization_id=o.id WHERE o.id=? AND m.user_uid=? LIMIT 1").bind(orgId,uid).first();
  if(!row||row.org_status!=='active'||row.member_status!=='active')fail(404,'WORKSPACE_NOT_FOUND','Workspace was not found or access is not permitted.');
  if(!roles.has(row.role))fail(403,'INSUFFICIENT_ROLE','You do not have permission to perform this action.');
  return row;
}
async function projectAccess(db,uid,orgId,projectId,roles=READ) {
  const org=await orgAccess(db,uid,orgId,roles);
  idValue(projectId,'projectId');
  const project=await db.prepare("SELECT id,organization_id,name,type,location,status,created_at,updated_at FROM projects WHERE id=? AND organization_id=? AND status='active' LIMIT 1").bind(projectId,orgId).first();
  if(!project)fail(404,'PROJECT_NOT_FOUND','Project was not found or access is not permitted.');
  return {org,project};
}
function average(values){return values.reduce((sum,n)=>sum+n,0)/values.length;}
function consecutive(dates){for(let i=1;i<dates.length;i++){if(Date.parse(dates[i]+'T00:00:00Z')-Date.parse(dates[i-1]+'T00:00:00Z')!==86400000)return false;}return true;}
function linearForecast(values){
  const xs=values.map((_,i)=>i),mx=average(xs),my=average(values);let cov=0,variance=0;
  xs.forEach((x,i)=>{cov+=(x-mx)*(values[i]-my);variance+=(x-mx)*(x-mx);});
  const slope=variance?cov/variance:0,intercept=my-slope*mx;
  const dailyEstimates=Array.from({length:7},(_,i)=>Math.max(0,intercept+slope*(values.length+i)));
  return {days:7,dailyEstimates,averagePerDay:average(dailyEstimates),method:'Ordinary least-squares trend from 28 consecutive daily observations; seven-day point estimate.'};
}
function analyticsFor(records){
  const seriesMap=new Map();
  for(const r of records){const key=r.platform.toLowerCase()+'|||'+r.metric.toLowerCase();if(!seriesMap.has(key))seriesMap.set(key,{platform:r.platform,metric:r.metric,byDate:new Map()});seriesMap.get(key).byDate.set(r.date,Number(r.value));}
  const coverage=[],comparisons=[],forecasts=[];
  for(const series of seriesMap.values()){
    const dates=Array.from(series.byDate.keys()).sort();
    coverage.push({platform:series.platform,metric:series.metric,observations:dates.length,firstDate:dates[0]||null,latestDate:dates[dates.length-1]||null,consecutive14DayWindow:dates.length>=14&&consecutive(dates.slice(-14)),consecutive28DayWindow:dates.length>=28&&consecutive(dates.slice(-28))});
    if(dates.length>=14){const ds=dates.slice(-14);if(consecutive(ds)){const v=ds.map(d=>series.byDate.get(d)),snapshot=/(followers?|subscribers?|members?_count|total_followers)/i.test(series.metric),prior=snapshot?v[6]:average(v.slice(0,7)),latest=snapshot?v[13]:average(v.slice(7,14));comparisons.push({platform:series.platform,metric:series.metric,comparisonType:snapshot?'snapshot_first_window_end_vs_latest_window_end':'daily_average_latest_7_vs_previous_7',previousPeriodValue:prior,latestPeriodValue:latest,absoluteChange:latest-prior,percentageChange:prior===0?null:(latest/prior-1)*100,startDate:ds[0],previousPeriodEnd:ds[6],latestPeriodStart:ds[7],endDate:ds[13],sourceVerified:false});}}
    if(dates.length>=28){const ds=dates.slice(-28);if(consecutive(ds)){const v=ds.map(d=>series.byDate.get(d)),f=linearForecast(v),baseline=average(v.slice(-7));forecasts.push({platform:series.platform,metric:series.metric,basedOnStartDate:ds[0],basedOnEndDate:ds[27],recent7DayAverage:baseline,...f,projectedAverageChangePercent:baseline===0?null:(f.averagePerDay/baseline-1)*100,sourceVerified:false,disclaimer:'Estimate only. Does not model seasonality, promotions, stock-outs, ranking changes or uncertainty.'});}}
  }
  return {coverage,comparisons,forecasts};
}
function metricOut(r){return {id:r.id,date:r.date,platform:r.platform,metric:r.metric,value:Number(r.value),source:r.source||null,sourceVerified:r.source_verified===1,importedAt:r.imported_at||null};}
async function metricRows(db,projectId,start=null,end=null,limit=1000){
  let sql='SELECT id,date,platform,platform_key,metric,metric_key,value,source,source_verified,imported_at FROM metrics WHERE project_id=?';const args=[projectId];
  if(start){sql+=' AND date>=?';args.push(start);}if(end){sql+=' AND date<=?';args.push(end);}
  sql+=' ORDER BY date DESC,platform ASC,metric ASC LIMIT ?';args.push(limit);
  const result=await db.prepare(sql).bind(...args).all();return result.results||[];
}
async function readFinancial(db,projectId,start,end){
  let ss="SELECT currency,SUM(value) total,COUNT(*) rows,MIN(source_verified) verified FROM sales_observations WHERE project_id=? AND metric='revenue'",cs='SELECT currency,SUM(amount) total,COUNT(*) rows FROM business_costs WHERE project_id=?';
  const sa=[projectId],ca=[projectId];if(start){ss+=' AND date>=?';sa.push(start);cs+=' AND date>=?';ca.push(start);}if(end){ss+=' AND date<=?';sa.push(end);cs+=' AND date<=?';ca.push(end);}ss+=' GROUP BY currency';cs+=' GROUP BY currency';
  const [sales,costs]=await Promise.all([db.prepare(ss).bind(...sa).all(),db.prepare(cs).bind(...ca).all()]);
  const map=new Map();
  for(const r of sales.results||[])map.set(r.currency,{currency:r.currency,reportedRevenue:Number(r.total||0),recordedCosts:0,revenueRows:r.rows,allRevenueRowsVerified:r.verified===1});
  for(const r of costs.results||[]){const item=map.get(r.currency)||{currency:r.currency,reportedRevenue:0,recordedCosts:0,revenueRows:0,allRevenueRowsVerified:false};item.recordedCosts=Number(r.total||0);item.costRows=r.rows;map.set(r.currency,item);}
  return Array.from(map.values()).map(r=>({...r,revenueMinusRecordedCosts:r.reportedRevenue-r.recordedCosts,label:'Revenue minus entered costs — not net profit',sourceVerified:false}));
}
async function hashValue(value){const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value));return Array.from(new Uint8Array(digest)).map(b=>b.toString(16).padStart(2,'0')).join('');}
function randomSecret(){const raw=crypto.getRandomValues(new Uint8Array(32));let binary='';for(const b of raw)binary+=String.fromCharCode(b);return btoa(binary).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');}
function mcpToolDefinitions(){
  const schema={type:'object',properties:{projectId:{type:'string',description:'Project identifier. Required for workspace-wide tokens; ignored when token is limited to one project.'},startDate:{type:'string'},endDate:{type:'string'},limit:{type:'integer',minimum:1,maximum:100}},additionalProperties:false};
  return [
    {name:'list_projects',description:'List projects in the authorized workspace.',inputSchema:{type:'object',properties:{},additionalProperties:false},annotations:{readOnlyHint:true,destructiveHint:false,openWorldHint:false}},
    {name:'get_metrics',description:'Read source-labelled observations. User imports are unverified by default and missing dates are not zero.',inputSchema:schema,annotations:{readOnlyHint:true,destructiveHint:false,openWorldHint:false}},
    {name:'get_growth_report',description:'Read 14-day growth comparisons and seven-day trend estimates only when the complete consecutive history exists.',inputSchema:schema,annotations:{readOnlyHint:true,destructiveHint:false,openWorldHint:false}},
    {name:'get_financial_report',description:'Read revenue and entered cost reconciliation grouped by currency. This is not net profit.',inputSchema:schema,annotations:{readOnlyHint:true,destructiveHint:false,openWorldHint:false}},
    {name:'list_sales',description:'Read entered/imported sales observations.',inputSchema:schema,annotations:{readOnlyHint:true,destructiveHint:false,openWorldHint:false}},
    {name:'list_costs',description:'Read entered cost observations.',inputSchema:schema,annotations:{readOnlyHint:true,destructiveHint:false,openWorldHint:false}},
    {name:'list_content_drafts',description:'Read project content drafts; drafts are not published posts.',inputSchema:schema,annotations:{readOnlyHint:true,destructiveHint:false,openWorldHint:false}},
    {name:'list_integrations',description:'Read integration status metadata only; never exposes credentials or proves an unverified connection is live.',inputSchema:schema,annotations:{readOnlyHint:true,destructiveHint:false,openWorldHint:false}}
  ];
}
async function requireMcpToken(request,env){
  const m=(request.headers.get('Authorization')||'').match(/^Bearer\s+(ajnxt_mcp_[A-Za-z0-9_-]{30,})$/);
  if(!m)fail(401,'MCP_TOKEN_REQUIRED','Provide the AJAYNXT read-only MCP bearer token.');
  const hash=await hashValue(m[1]);
  const t=await env.DB.prepare("SELECT id,label,organization_id,project_id,owner_uid,status,expires_at,last_used_at FROM mcp_tokens WHERE token_hash=? AND status='active' AND expires_at>CURRENT_TIMESTAMP LIMIT 1").bind(hash).first();
  if(!t)fail(401,'MCP_TOKEN_INVALID','MCP token is invalid, expired or revoked.');
  await orgAccess(env.DB,t.owner_uid,t.organization_id);
  if(t.project_id)await projectAccess(env.DB,t.owner_uid,t.organization_id,t.project_id);
  if(!t.last_used_at||Date.parse(String(t.last_used_at).replace(' ','T')+'Z')<Date.now()-5*60*1000)await env.DB.prepare("UPDATE mcp_tokens SET last_used_at=CURRENT_TIMESTAMP WHERE id=? AND (last_used_at IS NULL OR last_used_at<datetime('now','-5 minutes'))").bind(t.id).run();
  return t;
}
async function resolveMcpProject(db,token,args){
  const id=args&&args.projectId?args.projectId:token.project_id;
  if(!id)fail(400,'PROJECT_ID_REQUIRED','Specify projectId for this workspace-wide token.');
  if(token.project_id&&id!==token.project_id)fail(403,'MCP_SCOPE_DENIED','This token is restricted to another project.');
  return (await projectAccess(db,token.owner_uid,token.organization_id,id)).project;
}
async function callMcpTool(db,token,name,args){
  args=args&&typeof args==='object'&&!Array.isArray(args)?args:{};
  const range=dateRange(new URLSearchParams({...(args.startDate?{startDate:args.startDate}:{}),...(args.endDate?{endDate:args.endDate}:{})}));
  if(name==='list_projects'){
    const rows=token.project_id
      ?await db.prepare("SELECT id,name,type,location,status,created_at FROM projects WHERE id=? AND organization_id=? AND status='active'").bind(token.project_id,token.organization_id).all()
      :await db.prepare("SELECT id,name,type,location,status,created_at FROM projects WHERE organization_id=? AND status='active' ORDER BY created_at LIMIT 200").bind(token.organization_id).all();
    return {workspaceId:token.organization_id,projects:rows.results||[]};
  }
  const p=await resolveMcpProject(db,token,args);
  if(name==='get_metrics'){
    let limit=Number.isInteger(args.limit)?args.limit:100;limit=Math.max(1,Math.min(100,limit));
    const rows=await metricRows(db,p.id,range.start,range.end,limit);
    return {project:{id:p.id,name:p.name},count:rows.length,metrics:rows.map(metricOut),note:'Imported source values are not independently verified unless sourceVerified is true.'};
  }
  if(name==='get_growth_report'){
    const rows=await metricRows(db,p.id,range.start,range.end,2000),data=rows.slice().reverse();
    return {project:{id:p.id,name:p.name},recordCount:rows.length,...analyticsFor(data),disclaimers:['Imported source records have not been independently verified.','Missing dates are not zero.','Forecasts are trend estimates, not promises.']};
  }
  if(name==='get_financial_report')return {project:{id:p.id,name:p.name},totals:await readFinancial(db,p.id,range.start,range.end),disclaimers:['Manual/imported entries are not verified by default.','Revenue minus entered costs is not net profit.','Different currencies are not combined.']};
  if(name==='list_sales'||name==='list_costs'){
    const isSales=name==='list_sales';let sql=isSales?'SELECT id,date,source,metric,value,currency,source_verified,imported_at FROM sales_observations WHERE project_id=?':'SELECT id,date,category,amount,currency,description,source,created_at FROM business_costs WHERE project_id=?';
    const argsSql=[p.id];if(range.start){sql+=' AND date>=?';argsSql.push(range.start);}if(range.end){sql+=' AND date<=?';argsSql.push(range.end);}sql+=' ORDER BY date DESC LIMIT 100';
    const rows=await db.prepare(sql).bind(...argsSql).all();return {project:{id:p.id,name:p.name},[isSales?'sales':'costs']:rows.results||[]};
  }
  if(name==='list_content_drafts'){
    const rows=await db.prepare("SELECT id,title,copy_text,platforms_json,status,created_at,updated_at FROM content_drafts WHERE project_id=? AND status<>'archived' ORDER BY updated_at DESC LIMIT 100").bind(p.id).all();
    return {project:{id:p.id,name:p.name},drafts:(rows.results||[]).map(d=>({id:d.id,title:d.title,copy:d.copy_text,platforms:JSON.parse(d.platforms_json||'[]'),status:d.status,createdAt:d.created_at,updatedAt:d.updated_at,published:false}))};
  }
  if(name==='list_integrations'){
    const rows=await db.prepare('SELECT provider,account_name,status,scopes_json,last_verified_at,last_sync_at FROM integration_connections WHERE project_id=? ORDER BY provider LIMIT 100').bind(p.id).all();
    return {project:{id:p.id,name:p.name},integrations:(rows.results||[]).map(r=>({provider:r.provider,accountName:r.account_name,status:r.status,scopes:JSON.parse(r.scopes_json||'[]'),lastVerifiedAt:r.last_verified_at,lastSyncAt:r.last_sync_at})),note:'Connection metadata does not prove a live connection without verified status and successful sync.'};
  }
  fail(404,'MCP_TOOL_NOT_FOUND','Read-only MCP tool not found.');
}
async function mcpEndpoint(request,env){
  
  if(request.method!=='POST')return methodDenied(['POST']);
  checkMcpOrigin(request,env);
  let token;
  try{token=await requireMcpToken(request,env);}
  catch(error){
    if(error instanceof ApiError&&error.status===401){
      const origin=new URL(request.url).origin;
      return reply({error:error.code,message:error.message},401,{'WWW-Authenticate':'Bearer resource_metadata="'+origin+'/.well-known/oauth-protected-resource/mcp", scope="mcp:read"'});
    }
    throw error;
  }
  const b=await bodyJson(request,65536);
  if(b.jsonrpc!=='2.0'||typeof b.method!=='string')return reply({jsonrpc:'2.0',id:b.id??null,error:{code:-32600,message:'Invalid JSON-RPC request.'}},400);
  const id=b.id===undefined?null:b.id,version=b.params&&typeof b.params.protocolVersion==='string'?b.params.protocolVersion:'2025-11-25';
  if(b.method.startsWith('notifications/'))return new Response(null,{status:202,headers:{'Cache-Control':'no-store'}});
  if(b.method==='ping')return reply({jsonrpc:'2.0',id,result:{}},200,{'MCP-Protocol-Version':version});
  if(b.method==='initialize')return reply({jsonrpc:'2.0',id,result:{protocolVersion:['2026-07-28','2025-11-25','2025-06-18','2024-11-05'].includes(version)?version:'2025-11-25',capabilities:{tools:{listChanged:false}},serverInfo:{name:'AJAYNXT Social Hub Read-only',version:'0.2.0'},instructions:'Read only. This server cannot create, update, publish or delete data and does not expose credentials. Imported values can be unverified. Revenue minus recorded costs is not net profit.'}},200,{'MCP-Protocol-Version':version});
  if(b.method==='tools/list')return reply({jsonrpc:'2.0',id,result:{tools:mcpToolDefinitions()}},200,{'MCP-Protocol-Version':version});
  if(b.method==='tools/call'){
    try{const result=await callMcpTool(env.DB,token,b.params&&b.params.name,b.params&&b.params.arguments);return reply({jsonrpc:'2.0',id,result:{content:[{type:'text',text:JSON.stringify(result)}],structuredContent:result,isError:false}},200,{'MCP-Protocol-Version':version});}
    catch(e){return reply({jsonrpc:'2.0',id,result:{content:[{type:'text',text:e instanceof ApiError?e.message:'Read tool failed. Check access scope or data availability.'}],isError:true}},200,{'MCP-Protocol-Version':version});}
  }
  return reply({jsonrpc:'2.0',id,error:{code:-32601,message:'Method not found.'}},200,{'MCP-Protocol-Version':version});
}
async function purgeOldRows(db,table,dateColumn,cutoffExpression="datetime('now','-365 days')"){
  let total=0;
  for(let i=0;i<RETENTION_BATCHES_PER_TABLE;i++){
    const sql="DELETE FROM "+table+" WHERE id IN (SELECT id FROM "+table+" WHERE "+dateColumn+"<"+cutoffExpression+" LIMIT "+RETENTION_BATCH_SIZE+")";
    const result=await db.prepare(sql).run(),deleted=Number(result.meta&&result.meta.changes||0);
    total+=deleted;if(deleted<RETENTION_BATCH_SIZE)break;
  }
  return total;
}
function checkMcpOrigin(request,env){
  const origin=request.headers.get('Origin');if(!origin)return;
  const allowed=new Set();
  if(env.APP_ORIGIN){try{allowed.add(new URL(env.APP_ORIGIN).origin);}catch{}}
  if(env.MCP_ALLOWED_ORIGINS){for(const value of env.MCP_ALLOWED_ORIGINS.split(',')){try{allowed.add(new URL(value.trim()).origin);}catch{}}}
  let actual;try{actual=new URL(origin).origin;}catch{fail(403,'ORIGIN_NOT_ALLOWED','MCP origin is invalid.');}
  if(!allowed.has(actual))fail(403,'ORIGIN_NOT_ALLOWED','MCP client origin is not allowlisted.');
}

async function purgeOldScheduledPosts(db){
  let total=0;
  for(let i=0;i<RETENTION_BATCHES_PER_TABLE;i++){
    const sql="DELETE FROM scheduled_posts WHERE id IN (SELECT id FROM scheduled_posts WHERE created_at<datetime('now','-365 days') AND (status IN ('draft','published','failed','cancelled','needs_connection') OR (status='scheduled' AND scheduled_at<datetime('now','-365 days'))) LIMIT "+RETENTION_BATCH_SIZE+")";
    const result=await db.prepare(sql).run(),deleted=Number(result.meta&&result.meta.changes||0);
    total+=deleted;if(deleted<RETENTION_BATCH_SIZE)break;
  }
  return total;
}

async function runRetention(env){
  const db=env.DB,runId=crypto.randomUUID();
  await db.prepare("INSERT INTO retention_runs(id,started_at,status) VALUES(?,CURRENT_TIMESTAMP,'running')").bind(runId).run();
  const stats={metrics:0,sales:0,costs:0,reports:0,drafts:0,scheduledPosts:0,auditEvents:0,expiredMcpTokens:0,oauthRecords:0};
  try{
    stats.metrics=await purgeOldRows(db,'metrics','date',"date('now','-365 days')");
    stats.sales=await purgeOldRows(db,'sales_observations','date',"date('now','-365 days')");
    stats.costs=await purgeOldRows(db,'business_costs','date',"date('now','-365 days')");
    stats.reports=await purgeOldRows(db,'reports','generated_at');
    stats.scheduledPosts=await purgeOldScheduledPosts(db);
    await db.prepare("UPDATE scheduled_posts SET draft_id=NULL WHERE draft_id IN (SELECT id FROM content_drafts WHERE updated_at<datetime('now','-365 days'))").run();
    stats.drafts=await purgeOldRows(db,'content_drafts','updated_at');
    stats.auditEvents=await purgeOldRows(db,'audit_events','created_at');
    let expired=0;
    for(let i=0;i<RETENTION_BATCHES_PER_TABLE;i++){const r=await db.prepare("DELETE FROM mcp_tokens WHERE id IN (SELECT id FROM mcp_tokens t WHERE (t.expires_at<datetime('now','-30 days') OR t.revoked_at<datetime('now','-30 days')) AND NOT EXISTS (SELECT 1 FROM oauth_refresh_tokens rt WHERE rt.family_id=t.id) LIMIT 250)").run(),n=Number(r.meta&&r.meta.changes||0);expired+=n;if(n<250)break;}
    stats.expiredMcpTokens=expired;
    for(const [table,sql] of [
      ['sessions',"DELETE FROM oauth_sessions WHERE expires_at<datetime('now','-1 day')"],
      ['requests',"DELETE FROM oauth_requests WHERE expires_at<datetime('now','-1 day')"],
      ['codes',"DELETE FROM oauth_codes WHERE expires_at<datetime('now','-1 day') OR used_at<datetime('now','-365 days')"],
      ['refresh',"DELETE FROM oauth_refresh_tokens WHERE expires_at<datetime('now','-30 days') OR revoked_at<datetime('now','-30 days')"]
    ]){const removed=await db.prepare(sql).run();stats.oauthRecords+=Number(removed.meta&&removed.meta.changes||0);}
    const rateEvents=await db.prepare("DELETE FROM oauth_registration_events WHERE created_at<datetime('now','-7 days')").run();
    stats.oauthRecords+=Number(rateEvents.meta&&rateEvents.meta.changes||0);
    // Remove stale connection catalog entries only if disconnected for more than a year.
    await db.prepare("DELETE FROM integration_connections WHERE status IN ('revoked','not_connected','import_required','error') AND updated_at<datetime('now','-365 days')").run();
    await db.prepare("UPDATE retention_runs SET finished_at=CURRENT_TIMESTAMP,deleted_metrics=?,deleted_sales=?,deleted_costs=?,deleted_reports=?,deleted_drafts=?,deleted_scheduled_posts=?,deleted_audit_events=?,deleted_expired_mcp_tokens=?,deleted_oauth_records=?,status='complete' WHERE id=?")
      .bind(stats.metrics,stats.sales,stats.costs,stats.reports,stats.drafts,stats.scheduledPosts,stats.auditEvents,stats.expiredMcpTokens,stats.oauthRecords,runId).run();
    await db.prepare("DELETE FROM retention_runs WHERE started_at<datetime('now','-365 days')").run();
    return {runId,stats};
  }catch(error){
    await db.prepare("UPDATE retention_runs SET finished_at=CURRENT_TIMESTAMP,status='partial',error_code=? WHERE id=?").bind(error&&error.code?String(error.code).slice(0,80):'RETENTION_ERROR',runId).run().catch(()=>{});
    console.error('AJAYNXT retention job failed', {runId});
    throw error;
  }
}
function htmlEscape(value){
  return String(value==null?'':value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function htmlResponse(html,status=200,headers={}){
  const h=new Headers(headers);h.set('Content-Type','text/html; charset=utf-8');h.set('Cache-Control','no-store, max-age=0');h.set('X-Content-Type-Options','nosniff');h.set('X-Frame-Options','DENY');h.set('Referrer-Policy','no-referrer');return new Response(html,{status,headers:h});
}
function sqlTime(milliseconds){return new Date(milliseconds).toISOString().replace('T',' ').slice(0,19);}
function requestCookie(request){
  const raw=request.headers.get('Cookie')||'',match=raw.match(/(?:^|;\s*)ajnxt_oauth_session=([A-Za-z0-9_-]+)/);
  return match?match[1]:null;
}
async function oauthSession(request,db){
  const raw=requestCookie(request);if(!raw)return null;
  const hash=await hashValue(raw);
  return await db.prepare("SELECT session_hash,user_uid,expires_at FROM oauth_sessions WHERE session_hash=? AND expires_at>CURRENT_TIMESTAMP LIMIT 1").bind(hash).first();
}
async function validOAuthRequest(db,tx){
  if(typeof tx!=='string'||!/^[A-Za-z0-9_-]{12,80}$/.test(tx))fail(400,'INVALID_OAUTH_REQUEST','OAuth transaction is invalid.');
  const request=await db.prepare("SELECT * FROM oauth_requests WHERE id=? AND expires_at>CURRENT_TIMESTAMP LIMIT 1").bind(tx).first();
  if(!request)fail(400,'OAUTH_REQUEST_EXPIRED','The authorization request expired. Start the connection again.');
  return request;
}
function secureRedirectUri(value){
  let uri;try{uri=new URL(value);}catch{fail(400,'INVALID_REDIRECT_URI','Redirect URI must be an absolute URL.');}
  if(uri.hash)fail(400,'INVALID_REDIRECT_URI','Redirect URI must not contain a fragment.');
  const local=['localhost','127.0.0.1','[::1]'].includes(uri.hostname);
  if(uri.protocol!=='https:'&&!(uri.protocol==='http:'&&local))fail(400,'INVALID_REDIRECT_URI','Redirect URI must use HTTPS, except loopback development URLs.');
  return uri;
}
function oauthMeta(origin){
  return {issuer:origin,authorization_endpoint:origin+'/oauth/authorize',token_endpoint:origin+'/oauth/token',registration_endpoint:origin+'/oauth/register',response_types_supported:['code'],response_modes_supported:['query'],grant_types_supported:['authorization_code','refresh_token'],token_endpoint_auth_methods_supported:['none','client_secret_post','client_secret_basic'],code_challenge_methods_supported:['S256'],scopes_supported:['mcp:read','offline_access'],service_documentation:'https://github.com/ajaynxt/ajaynxt-superapp/blob/main/docs/CLOUDFLARE-SETUP.md',resource_parameter_supported:true};
}
function loginHtml(tx,env){
  const script='<script type="module">const tx='+JSON.stringify(tx)+';const status=document.getElementById("status");async function run(){try{const cfgRes=await fetch("/api/config",{cache:"no-store"});const cfg=await cfgRes.json();if(!cfgRes.ok||!cfg.configured)throw new Error(cfg.message||"Sign-in is not configured.");const sdk="https://www.gstatic.com/firebasejs/12.19.0/";const appSdk=await import(sdk+"firebase-app.js");const authSdk=await import(sdk+"firebase-auth.js");const app=appSdk.initializeApp(cfg.config);const auth=authSdk.getAuth(app);let stop;const current=await new Promise(resolve=>{stop=authSdk.onAuthStateChanged(auth,u=>{stop();resolve(u)})});let user=current;if(!user){const result=await authSdk.signInWithPopup(auth,new authSdk.GoogleAuthProvider());user=result.user;}const token=await user.getIdToken();const response=await fetch("/oauth/session",{method:"POST",headers:{"Authorization":"Bearer "+token,"Content-Type":"application/json"},body:JSON.stringify({tx}),cache:"no-store"});const out=await response.json();if(!response.ok)throw new Error(out.message||"Sign-in failed.");window.location.replace("/oauth/consent?tx="+encodeURIComponent(tx));}catch(e){status.textContent=e.message||"Sign-in could not be completed.";}}document.getElementById("login").addEventListener("click",run);</script>';
  return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorize AJAYNXT Social Hub</title><style>body{margin:0;background:#111318;color:#f6f7fb;font:16px/1.5 system-ui;display:grid;place-items:center;min-height:100vh}.box{max-width:440px;margin:20px;padding:28px;border:1px solid #303542;border-radius:18px;background:#191c24}button{background:#9294ff;color:#101117;border:0;border-radius:10px;padding:12px 18px;font-weight:700;cursor:pointer}p{color:#a8b0bf}.note{font-size:13px}</style></head><body><main class="box"><h1>Connect AJAYNXT Social Hub</h1><p>An AI client is requesting read-only access. Sign in with Google, then choose exactly which workspace and project to share.</p><button id="login">Continue with Google</button><p class="note" id="status" role="status">Click Continue with Google to sign in.</p><p class="note">This connection cannot publish, modify settings, create Admin IDs or delete records.</p></main>'+script+'</body></html>';
}
function consentHtml(tx,user,workspaces,projects){
  const wsOptions=workspaces.map(w=>'<option value="'+htmlEscape(w.id)+'">'+htmlEscape(w.name)+' · '+htmlEscape(w.role)+'</option>').join('');
  const projectOptions=projects.map(p=>'<option data-org="'+htmlEscape(p.organization_id)+'" value="'+htmlEscape(p.id)+'">'+htmlEscape(p.name)+' · '+htmlEscape(p.organization_name)+'</option>').join('');
  const script='<script>const org=document.getElementById("organizationId"),project=document.getElementById("projectId");function filter(){for(const op of project.options){if(!op.value){op.hidden=false;continue;}op.hidden=op.dataset.org!==org.value;}if(project.selectedOptions[0]&&project.selectedOptions[0].hidden)project.value="";}org.addEventListener("change",filter);filter();</script>';
  return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorize read-only access</title><style>body{margin:0;background:#111318;color:#f6f7fb;font:15px/1.5 system-ui;display:grid;place-items:center;min-height:100vh}.box{max-width:520px;margin:20px;padding:28px;border:1px solid #303542;border-radius:18px;background:#191c24}label{display:block;margin-top:16px;margin-bottom:6px}select,button{width:100%;padding:12px;border-radius:10px;border:1px solid #303542;background:#141720;color:#f6f7fb}button{margin-top:15px;cursor:pointer;font-weight:700}.allow{background:#9294ff;color:#101117}.note{color:#a8b0bf;font-size:13px}</style></head><body><main class="box"><h1>Approve read-only access</h1><p>Signed in as <b>'+htmlEscape(user.email||user.uid)+'</b>.</p><p>The connected AI client can read selected project metrics, growth reports, financial summaries, connection status and draft copy. It cannot post, alter settings or delete data. It may process the data under that AI provider’s own terms.</p><form method="post" action="/oauth/consent"><input type="hidden" name="tx" value="'+htmlEscape(tx)+'"><label for="organizationId">Workspace</label><select id="organizationId" name="organizationId" required>'+wsOptions+'</select><label for="projectId">Project scope</label><select id="projectId" name="projectId"><option value="">All projects in selected workspace (read-only)</option>'+projectOptions+'</select><button class="allow" name="decision" value="allow">Approve read-only access</button><button name="decision" value="deny">Deny</button></form><p class="note">You can revoke access later in the Social Hub Admin Console. Data older than 365 days is cleaned up automatically.</p></main>'+script+'</body></html>';
}
async function oauthEndpoint(request,env,url){
  const db=env.DB,path=url.pathname,method=request.method,origin=url.origin;
  if(path==='/oauth/register'){
    if(method!=='POST')return methodDenied(['POST']);
    const ip=request.headers.get('CF-Connecting-IP')||'unknown';
    if(!env.MCP_RATE_LIMIT_SALT)fail(503,'MCP_RATE_LIMIT_NOT_CONFIGURED','OAuth client registration is disabled until MCP_RATE_LIMIT_SALT is configured.');
    const ipHash=await hashValue(env.MCP_RATE_LIMIT_SALT+'|'+ip);
    const recent=await db.prepare("SELECT COUNT(*) AS total FROM oauth_registration_events WHERE ip_hash=? AND created_at>datetime('now','-1 hour')").bind(ipHash).first();
    if(Number(recent&&recent.total||0)>=20)fail(429,'OAUTH_REGISTRATION_RATE_LIMIT','Too many OAuth client registrations from this network. Try again later.');
    await db.prepare('INSERT INTO oauth_registration_events(id,ip_hash,created_at) VALUES(?,?,CURRENT_TIMESTAMP)').bind(crypto.randomUUID(),ipHash).run();
    const body=await bodyJson(request,32768),name=textValue(body.client_name||'Unnamed MCP client','Client name',100);
    if(!Array.isArray(body.redirect_uris)||body.redirect_uris.length<1||body.redirect_uris.length>10)fail(400,'INVALID_REDIRECT_URIS','Provide 1 to 10 exact redirect URIs.');
    const redirects=[...new Set(body.redirect_uris.map(value=>{secureRedirectUri(value);return value;}))];
    const grants=body.grant_types||['authorization_code','refresh_token'],responses=body.response_types||['code'];
    if(!Array.isArray(grants)||!grants.includes('authorization_code')||!grants.includes('refresh_token'))fail(400,'INVALID_GRANT_TYPES','Use authorization_code and refresh_token grants.');
    if(!Array.isArray(responses)||!responses.includes('code'))fail(400,'INVALID_RESPONSE_TYPES','Only the code response type is supported.');
    const authMethod=body.token_endpoint_auth_method||'none';
    if(!['none','client_secret_post','client_secret_basic'].includes(authMethod))fail(400,'INVALID_TOKEN_AUTH_METHOD','Unsupported client authentication method.');
    const clientId='ajnxt-client-'+crypto.randomUUID().replaceAll('-',''),clientSecret=authMethod==='none'?null:'ajnxt_secret_'+randomSecret(),secretHash=clientSecret?await hashValue(clientSecret):null;
    await db.prepare("INSERT INTO oauth_clients(client_id,client_name,redirect_uris_json,token_endpoint_auth_method,client_secret_hash,status,created_at) VALUES(?,?,?,?,?,'active',CURRENT_TIMESTAMP)").bind(clientId,name,JSON.stringify(redirects),authMethod,secretHash).run();
    return reply({client_id:clientId,client_name:name,redirect_uris:redirects,grant_types:grants,response_types:responses,token_endpoint_auth_method:authMethod,...(clientSecret?{client_secret:clientSecret,client_secret_expires_at:0}:{})},201);
  }
  if(path==='/oauth/authorize'){
    if(method!=='GET')return methodDenied(['GET']);
    const q=url.searchParams,clientId=q.get('client_id'),redirectUri=q.get('redirect_uri'),state=q.get('state'),challenge=q.get('code_challenge'),challengeMethod=q.get('code_challenge_method'),scope=(q.get('scope')||'').trim(),resource=q.get('resource')||origin+'/mcp';
    if(q.get('response_type')!=='code'||!state||state.length>512||!challenge||challengeMethod!=='S256')fail(400,'INVALID_AUTHORIZATION_REQUEST','Authorization requires response_type=code, state and S256 PKCE.');
    const requestedScopes=scope.split(/\s+/).filter(Boolean);
    if(!requestedScopes.includes('mcp:read')||requestedScopes.some(value=>!['mcp:read','offline_access'].includes(value)))fail(400,'INVALID_SCOPE','Supported scopes are mcp:read and optional offline_access.');
    if(resource!==origin+'/mcp')fail(400,'INVALID_RESOURCE','Resource must be this server’s /mcp endpoint.');
    const client=await db.prepare("SELECT client_id,client_name,redirect_uris_json,status FROM oauth_clients WHERE client_id=? AND status='active' LIMIT 1").bind(clientId).first();
    if(!client)fail(400,'INVALID_CLIENT','OAuth client is not registered.');
    let redirects;try{redirects=JSON.parse(client.redirect_uris_json);}catch{redirects=[];}
    if(!redirects.includes(redirectUri))fail(400,'INVALID_REDIRECT_URI','Redirect URI does not exactly match registered configuration.');
    secureRedirectUri(redirectUri);
    const tx=crypto.randomUUID().replaceAll('-',''),expires=sqlTime(Date.now()+10*60*1000);
    await db.prepare("INSERT INTO oauth_requests(id,client_id,state,redirect_uri,code_challenge,code_challenge_method,scope,resource,expires_at,created_at) VALUES(?,?,?,?,?,'S256',?,?,?,CURRENT_TIMESTAMP)").bind(tx,clientId,state,redirectUri,challenge,scope,resource,expires).run();
    const session=await oauthSession(request,db);
    if(session){await db.prepare('UPDATE oauth_requests SET user_uid=? WHERE id=?').bind(session.user_uid,tx).run();return Response.redirect(origin+'/oauth/consent?tx='+encodeURIComponent(tx),302);}
    return htmlResponse(loginHtml(tx,env));
  }
  if(path==='/oauth/session'){
    if(method!=='POST')return methodDenied(['POST']);
    checkOrigin(request,env);
    const user=await requireUser(request,env),body=await bodyJson(request,4096),tx=await validOAuthRequest(db,body.tx);
    await rememberUser(db,user);await db.prepare('UPDATE oauth_requests SET user_uid=? WHERE id=?').bind(user.uid,tx.id).run();
    const cookie=randomSecret(),hash=await hashValue(cookie),expires=sqlTime(Date.now()+10*60*1000);
    await db.prepare("INSERT INTO oauth_sessions(session_hash,user_uid,expires_at,created_at) VALUES(?,?,?,CURRENT_TIMESTAMP)").bind(hash,user.uid,expires).run();
    return reply({signedIn:true},200,{'Set-Cookie':'ajnxt_oauth_session='+cookie+'; HttpOnly; SameSite=Lax; Path=/oauth; Max-Age=600'+(url.protocol==='https:'?'; Secure':'')});
  }
  if(path==='/oauth/consent'){
    const txId=url.searchParams.get('tx');
    if(method==='GET'){
      const tx=await validOAuthRequest(db,txId),session=await oauthSession(request,db);
      if(!session)return htmlResponse(loginHtml(tx.id,env));
      if(tx.user_uid&&tx.user_uid!==session.user_uid)fail(403,'OAUTH_SESSION_MISMATCH','Signed-in account does not match this authorization.');
      const [ws,projects]=await Promise.all([
        db.prepare("SELECT o.id,o.name,m.role FROM organizations o JOIN org_members m ON m.organization_id=o.id WHERE m.user_uid=? AND m.status='active' AND o.status='active' ORDER BY o.name").bind(session.user_uid).all(),
        db.prepare("SELECT p.id,p.name,p.organization_id,o.name organization_name FROM projects p JOIN organizations o ON o.id=p.organization_id JOIN org_members m ON m.organization_id=o.id WHERE m.user_uid=? AND m.status='active' AND p.status='active' AND o.status='active' ORDER BY o.name,p.name").bind(session.user_uid).all()
      ]);
      if(!(ws.results||[]).length)return htmlResponse('<!doctype html><meta charset="utf-8"><h1>No authorized workspace</h1><p>This Google account has no Social Hub workspace access.</p>',403);
      return htmlResponse(consentHtml(tx.id,{uid:session.user_uid},ws.results,projects.results||[]));
    }
    if(method==='POST'){
      checkOrigin(request,env);const session=await oauthSession(request,db);if(!session)fail(401,'OAUTH_LOGIN_REQUIRED','Sign in again to authorize.');
      const form=await request.formData(),txId=String(form.get('tx')||''),decision=String(form.get('decision')||'deny'),orgId=String(form.get('organizationId')||''),projectId=String(form.get('projectId')||'');
      const tx=await validOAuthRequest(db,txId);if(tx.user_uid&&tx.user_uid!==session.user_uid)fail(403,'OAUTH_SESSION_MISMATCH','Signed-in account does not match this authorization.');
      if(decision!=='allow'){
        await db.prepare('DELETE FROM oauth_requests WHERE id=?').bind(txId).run();
        const denied=new URL(tx.redirect_uri);denied.searchParams.set('error','access_denied');denied.searchParams.set('error_description','The user denied read-only access.');denied.searchParams.set('state',tx.state);
        return Response.redirect(denied.toString(),302);
      }
      await orgAccess(db,session.user_uid,orgId,READ);if(projectId)await projectAccess(db,session.user_uid,orgId,projectId,READ);
      const code='ajnxt_code_'+randomSecret(),codeHash=await hashValue(code),codeId=crypto.randomUUID(),expiry=sqlTime(Date.now()+120*1000);
      await db.prepare("INSERT INTO oauth_codes(id,code_hash,client_id,user_uid,organization_id,project_id,redirect_uri,code_challenge,scope,resource,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)").bind(codeId,codeHash,tx.client_id,session.user_uid,orgId,projectId||null,tx.redirect_uri,tx.code_challenge,tx.scope,tx.resource,expiry).run();
      await db.prepare('DELETE FROM oauth_requests WHERE id=?').bind(txId).run();
      const redirect=new URL(tx.redirect_uri);redirect.searchParams.set('code',code);redirect.searchParams.set('state',tx.state);
      return new Response(null,{status:302,headers:{'Location':redirect.toString(),'Cache-Control':'no-store','Set-Cookie':'ajnxt_oauth_session=; HttpOnly; SameSite=Lax; Path=/oauth; Max-Age=0'+(url.protocol==='https:'?'; Secure':'')}});
    }
    return methodDenied(['GET','POST']);
  }
  if(path==='/oauth/token'){
    if(method!=='POST')return methodDenied(['POST']);
    const raw=await request.text();if(raw.length>32768)fail(413,'BODY_TOO_LARGE','Token request is too large.');
    const form=new URLSearchParams(raw),grant=form.get('grant_type'),clientId=form.get('client_id');
    let authClientId=clientId,clientSecret=form.get('client_secret');
    const authHeader=request.headers.get('Authorization')||'';
    if(authHeader.startsWith('Basic ')){try{const decoded=atob(authHeader.slice(6)),i=decoded.indexOf(':');authClientId=decoded.slice(0,i);clientSecret=decoded.slice(i+1);}catch{fail(401,'INVALID_CLIENT_AUTH','Client authentication failed.');}}
    const client=await db.prepare("SELECT client_id,client_name,token_endpoint_auth_method,client_secret_hash,status FROM oauth_clients WHERE client_id=? AND status='active' LIMIT 1").bind(authClientId||'').first();
    if(!client)fail(401,'INVALID_CLIENT','OAuth client is invalid or revoked.');
    if(client.token_endpoint_auth_method==='none'){if(authHeader)fail(401,'INVALID_CLIENT_AUTH','This client uses public-client authentication.');}
    else if(!clientSecret||!client.client_secret_hash||await hashValue(clientSecret)!==client.client_secret_hash)fail(401,'INVALID_CLIENT_AUTH','Client authentication failed.');
    if(grant==='authorization_code'){
      const code=form.get('code'),redirectUri=form.get('redirect_uri'),verifier=form.get('code_verifier');
      if(!code||!redirectUri||!verifier||verifier.length<43||verifier.length>128)fail(400,'INVALID_GRANT','Code, redirect URI and PKCE verifier are required.');
      const codeHash=await hashValue(code),authCode=await db.prepare("SELECT * FROM oauth_codes WHERE code_hash=? AND client_id=? AND redirect_uri=? AND used_at IS NULL AND expires_at>CURRENT_TIMESTAMP LIMIT 1").bind(codeHash,client.client_id,redirectUri).first();
      if(!authCode)fail(400,'INVALID_GRANT','Authorization code is expired, already used or does not match this client.');
      const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(verifier));let binary='';for(const byte of new Uint8Array(digest))binary+=String.fromCharCode(byte);
      const challenge=btoa(binary).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');
      if(challenge!==authCode.code_challenge)fail(400,'INVALID_GRANT','PKCE validation failed.');
      const consumed=await db.prepare("UPDATE oauth_codes SET used_at=CURRENT_TIMESTAMP WHERE id=? AND used_at IS NULL AND expires_at>CURRENT_TIMESTAMP RETURNING id").bind(authCode.id).first();
      if(!consumed)fail(400,'INVALID_GRANT','Authorization code has already been used.');
      const access='ajnxt_mcp_'+randomSecret(),accessHash=await hashValue(access),refresh='ajnxt_refresh_'+randomSecret(),refreshHash=await hashValue(refresh),family=crypto.randomUUID(),accessExpiry=sqlTime(Date.now()+3600*1000),refreshExpiry=sqlTime(Date.now()+90*86400000);
      await db.batch([
        db.prepare("INSERT INTO mcp_tokens(id,token_hash,label,organization_id,project_id,owner_uid,status,expires_at,created_by,created_at) VALUES(?,?,?,?,?,?,'active',?,?,CURRENT_TIMESTAMP)").bind(family,accessHash,'OAuth: '+client.client_name.slice(0,60),authCode.organization_id,authCode.project_id,authCode.user_uid,accessExpiry,authCode.user_uid),
        db.prepare("INSERT INTO oauth_refresh_tokens(id,token_hash,client_id,family_id,user_uid,organization_id,project_id,scope,resource,expires_at,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,'active',CURRENT_TIMESTAMP)").bind(crypto.randomUUID(),refreshHash,client.client_id,family,authCode.user_uid,authCode.organization_id,authCode.project_id,authCode.scope,authCode.resource,refreshExpiry)
      ]);
      await db.prepare('UPDATE oauth_clients SET last_used_at=CURRENT_TIMESTAMP WHERE client_id=?').bind(client.client_id).run();
      return reply({access_token:access,token_type:'Bearer',expires_in:3600,refresh_token:refresh,scope:authCode.scope,resource:authCode.resource});
    }
    if(grant==='refresh_token'){
      const rawRefresh=form.get('refresh_token');if(!rawRefresh)fail(400,'INVALID_GRANT','refresh_token is required.');
      const hash=await hashValue(rawRefresh),old=await db.prepare("SELECT * FROM oauth_refresh_tokens WHERE token_hash=? AND client_id=? AND status='active' AND expires_at>CURRENT_TIMESTAMP LIMIT 1").bind(hash,client.client_id).first();
      if(!old)fail(400,'INVALID_GRANT','Refresh token is invalid, expired or already used.');
      await orgAccess(db,old.user_uid,old.organization_id,READ);if(old.project_id)await projectAccess(db,old.user_uid,old.organization_id,old.project_id,READ);
      const family=await db.prepare("SELECT id FROM mcp_tokens WHERE id=? AND status='active' LIMIT 1").bind(old.family_id).first();
      if(!family)fail(400,'INVALID_GRANT','This OAuth session has been revoked.');
      const spent=await db.prepare("UPDATE oauth_refresh_tokens SET status='revoked',revoked_at=CURRENT_TIMESTAMP WHERE id=? AND status='active' AND expires_at>CURRENT_TIMESTAMP RETURNING id").bind(old.id).first();
      if(!spent)fail(400,'INVALID_GRANT','Refresh token was already rotated.');
      const access='ajnxt_mcp_'+randomSecret(),accessHash=await hashValue(access),refresh='ajnxt_refresh_'+randomSecret(),refreshHash=await hashValue(refresh),accessExpiry=sqlTime(Date.now()+3600*1000),refreshExpiry=sqlTime(Date.now()+90*86400000);
      const rotated=await db.prepare("UPDATE mcp_tokens SET token_hash=?,expires_at=?,last_used_at=NULL WHERE id=? AND status='active' RETURNING id").bind(accessHash,accessExpiry,old.family_id).first();
      if(!rotated)fail(400,'INVALID_GRANT','This OAuth session has been revoked.');
      await db.prepare("INSERT INTO oauth_refresh_tokens(id,token_hash,client_id,family_id,user_uid,organization_id,project_id,scope,resource,expires_at,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,'active',CURRENT_TIMESTAMP)").bind(crypto.randomUUID(),refreshHash,client.client_id,old.family_id,old.user_uid,old.organization_id,old.project_id,old.scope,old.resource,refreshExpiry).run();
      return reply({access_token:access,token_type:'Bearer',expires_in:3600,refresh_token:refresh,scope:old.scope,resource:old.resource});
    }
    fail(400,'UNSUPPORTED_GRANT','Supported grants are authorization_code and refresh_token.');
  }
  return null;
}

async function router(request,env){
  const url=new URL(request.url),path=url.pathname,method=request.method,db=env.DB;
  if(path==='/.well-known/oauth-authorization-server'){
    if(method!=='GET')return methodDenied(['GET']);
    return reply(oauthMeta(url.origin));
  }
  if(path==='/.well-known/oauth-protected-resource'||path==='/.well-known/oauth-protected-resource/mcp'){
    if(method!=='GET')return methodDenied(['GET']);
    return reply({resource:url.origin+'/mcp',authorization_servers:[url.origin],scopes_supported:['mcp:read'],bearer_methods_supported:['header'],resource_name:'AJAYNXT Social Hub read-only MCP'});
  }
  if(path.startsWith('/oauth/')){
    const oauth=await oauthEndpoint(request,env,url);
    if(oauth)return oauth;
  }
  if(path==='/mcp')return mcpEndpoint(request,env);
  checkOrigin(request,env);

  if(path==='/api/health'){
    if(method!=='GET')return methodDenied(['GET']);
    return reply({ok:true,service:'ajnxt-social-hub-worker',backendConfigured:Boolean(env.DB&&env.FIREBASE_PROJECT_ID&&env.FIREBASE_API_KEY&&env.FIREBASE_AUTH_DOMAIN&&env.FIREBASE_APP_ID),ownerAccessConfigured:Boolean(env.AJAYNXT_SUPER_ADMIN_UID),retentionDays:RETENTION_DAYS});
  }
  if(path==='/api/config'){
    if(method!=='GET')return methodDenied(['GET']);
    const config={apiKey:env.FIREBASE_API_KEY||'',authDomain:env.FIREBASE_AUTH_DOMAIN||'',projectId:env.FIREBASE_PROJECT_ID||'',appId:env.FIREBASE_APP_ID||'',storageBucket:env.FIREBASE_STORAGE_BUCKET||'',messagingSenderId:env.FIREBASE_MESSAGING_SENDER_ID||''};
    if(!config.apiKey||!config.authDomain||!config.projectId||!config.appId)return reply({configured:false,message:'Firebase Web App configuration is not set in Cloudflare Worker secrets.'},503);
    return reply({configured:true,config});
  }
  if(path==='/api/workspaces'){
    const user=await requireUser(request,env);
    if(method==='GET'){
      await rememberUser(db,user);
      const rows=await db.prepare("SELECT o.id,o.name,m.role,o.created_at FROM organizations o JOIN org_members m ON m.organization_id=o.id WHERE m.user_uid=? AND m.status='active' AND o.status='active' ORDER BY o.created_at LIMIT 50").bind(user.uid).all();
      return reply({workspaces:rows.results||[]});
    }
    if(method!=='POST')return methodDenied(['GET','POST']);
    requireOwner(user,env);await rememberUser(db,user);
    const body=await bodyJson(request,16384),name=textValue(body.name||'AJAYNXT Workspace','Workspace name',100);
    const existing=await db.prepare('SELECT id FROM organizations WHERE owner_uid=? LIMIT 1').bind(user.uid).first();
    if(existing)fail(409,'WORKSPACE_ALREADY_EXISTS','Your agency workspace already exists.');
    const orgId='org_'+crypto.randomUUID().replaceAll('-',''),projectId=crypto.randomUUID();
    await db.batch([
      db.prepare("INSERT INTO organizations(id,name,owner_uid,status,created_at,updated_at,schema_version) VALUES(?,?,?,'active',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,1)").bind(orgId,name,user.uid),
      db.prepare("INSERT INTO org_members(organization_id,user_uid,role,status,created_by,created_at) VALUES(?,?,'owner','active',?,CURRENT_TIMESTAMP)").bind(orgId,user.uid,user.uid),
      db.prepare("INSERT INTO projects(id,organization_id,name,name_lower,type,location,status,created_by,created_at,updated_at,schema_version) VALUES(?,?,'Diamond Restaurant','diamond restaurant','Restaurant','BCS Market, New Shimla','active',?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,1)").bind(projectId,orgId,user.uid),
      db.prepare("INSERT INTO audit_events(id,organization_id,actor_uid,action,resource_type,resource_id,created_at) VALUES(?,?,?,'workspace.created','organization',?,CURRENT_TIMESTAMP)").bind(crypto.randomUUID(),orgId,user.uid,orgId)
    ]);
    return reply({workspace:{id:orgId,name,role:'owner'},initialProject:{id:projectId,name:'Diamond Restaurant'}},201);
  }
  if(path==='/api/projects'){
    const user=await requireUser(request,env),orgId=url.searchParams.get('organizationId');
    if(!orgId)fail(400,'ORGANIZATION_ID_REQUIRED','organizationId is required.');
    if(method==='GET'){
      await orgAccess(db,user.uid,orgId);
      const rows=await db.prepare("SELECT id,name,type,location,status,created_at FROM projects WHERE organization_id=? AND status='active' ORDER BY created_at LIMIT 200").bind(orgId).all();
      return reply({projects:rows.results||[]});
    }
    if(method!=='POST')return methodDenied(['GET','POST']);
    await orgAccess(db,user.uid,orgId,ADMIN);
    const body=await bodyJson(request,16384),name=textValue(body.name,'Project name',90),type=textValue(body.type||'Other','Project type',60),location=textValue(body.location||'','Project location',120,false);
    if(await db.prepare("SELECT id FROM projects WHERE organization_id=? AND name_lower=? AND status='active' LIMIT 1").bind(orgId,name.toLowerCase()).first())fail(409,'PROJECT_NAME_EXISTS','A project with this name already exists.');
    const id=crypto.randomUUID();
    await db.batch([
      db.prepare("INSERT INTO projects(id,organization_id,name,name_lower,type,location,status,created_by,created_at,updated_at,schema_version) VALUES(?,?,?,?,?,?,'active',?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,1)").bind(id,orgId,name,name.toLowerCase(),type,location,user.uid),
      db.prepare("INSERT INTO audit_events(id,organization_id,actor_uid,action,resource_type,resource_id,created_at) VALUES(?,?,?,'project.created','project',?,CURRENT_TIMESTAMP)").bind(crypto.randomUUID(),orgId,user.uid,id)
    ]);
    return reply({project:{id,name,type,location,status:'active',createdAt:new Date().toISOString()}},201);
  }
  if(path==='/api/admin/admins'){
    const user=await requireUser(request,env);requireOwner(user,env);
    if(method==='GET'){const rows=await db.prepare('SELECT uid,admin_id,email,display_name,status,created_at,revoked_at FROM platform_admins ORDER BY created_at DESC LIMIT 500').all();return reply({admins:rows.results||[]});}
    if(method==='POST'){
      await rememberUser(db,user);
      const body=await bodyJson(request,16384),email=textValue(body.email,'Admin email',254).toLowerCase();
      if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))fail(400,'INVALID_EMAIL','Enter a valid email address.');
      if(email===user.email)fail(400,'CANNOT_PROMOTE_OWNER','The Super Admin cannot receive a regular Admin ID.');
      const target=await db.prepare('SELECT uid,email,display_name FROM users WHERE email=? LIMIT 1').bind(email).first();
      if(!target)fail(404,'USER_NOT_REGISTERED','This person must sign in to Social Hub once before an Admin ID can be created.');
      if(target.uid===user.uid)fail(400,'CANNOT_PROMOTE_OWNER','The Super Admin cannot receive a regular Admin ID.');
      const old=await db.prepare('SELECT admin_id,status FROM platform_admins WHERE uid=? LIMIT 1').bind(target.uid).first();
      if(old&&old.status==='active')fail(409,'ADMIN_ALREADY_EXISTS','This user already has an active Admin ID.');
      const adminId=old?old.admin_id:'AJN-ADM-'+crypto.randomUUID().replaceAll('-','').slice(0,8).toUpperCase();
      if(old)await db.prepare("UPDATE platform_admins SET status='active',revoked_at=NULL WHERE uid=?").bind(target.uid).run();
      else await db.prepare("INSERT INTO platform_admins(uid,admin_id,email,display_name,status,created_by,created_at) VALUES(?,?,?,?,'active',?,CURRENT_TIMESTAMP)").bind(target.uid,adminId,email,target.display_name||'',user.uid).run();
      await audit(db,user,'admin.created','platform_admin',target.uid);
      return reply({created:true,admin:{uid:target.uid,adminId,email,displayName:target.display_name||'',status:'active'}},201);
    }
    if(method==='DELETE'){
      const uid=url.searchParams.get('uid');if(!uid||uid===user.uid)fail(400,'INVALID_ADMIN_UID','A different Admin UID is required.');
      const target=await db.prepare("SELECT admin_id,status FROM platform_admins WHERE uid=? LIMIT 1").bind(uid).first();
      if(!target||target.status!=='active')fail(404,'ADMIN_NOT_FOUND','Active Admin ID was not found.');
      await db.batch([
        db.prepare("UPDATE platform_admins SET status='revoked',revoked_at=CURRENT_TIMESTAMP WHERE uid=?").bind(uid),
        db.prepare("UPDATE org_members SET status='revoked' WHERE user_uid=? AND role='admin'").bind(uid)
      ]);
      await audit(db,user,'admin.revoked','platform_admin',uid);
      return reply({revoked:true,uid,adminId:target.admin_id});
    }
    return methodDenied(['GET','POST','DELETE']);
  }
  if(path==='/api/admin/members'){
    const user=await requireUser(request,env);requireOwner(user,env);
    const orgId=url.searchParams.get('organizationId');if(!orgId)fail(400,'ORGANIZATION_ID_REQUIRED','organizationId is required.');
    await orgAccess(db,user.uid,orgId,ADMIN);
    if(method==='GET'){
      const rows=await db.prepare('SELECT m.user_uid uid,u.email,u.display_name,m.role,m.status,m.created_at FROM org_members m LEFT JOIN users u ON u.uid=m.user_uid WHERE m.organization_id=? ORDER BY m.created_at LIMIT 500').bind(orgId).all();
      return reply({members:rows.results||[]});
    }
    if(method==='POST'){
      const body=await bodyJson(request,16384),email=textValue(body.email,'Member email',254).toLowerCase(),role=textValue(body.role,'Role',40);
      if(!['operator','analyst','client_viewer','admin'].includes(role))fail(400,'INVALID_ROLE','Choose operator, analyst, client_viewer or admin.');
      const target=await db.prepare('SELECT uid,email,display_name FROM users WHERE email=? LIMIT 1').bind(email).first();
      if(!target)fail(404,'USER_NOT_REGISTERED','This person must sign in to Social Hub once before being added.');
      if(target.uid===user.uid)fail(400,'SELF_MEMBERSHIP','The Super Admin is already the workspace owner.');
      if(role==='admin'&&!await db.prepare("SELECT uid FROM platform_admins WHERE uid=? AND status='active' LIMIT 1").bind(target.uid).first())fail(403,'PLATFORM_ADMIN_REQUIRED','Create this platform Admin ID first; only Super Admin can do that.');
      const prior=await db.prepare('SELECT role,status FROM org_members WHERE organization_id=? AND user_uid=? LIMIT 1').bind(orgId,target.uid).first();
      if(prior&&prior.status==='active')fail(409,'MEMBER_ALREADY_EXISTS','This user is already an active workspace member.');
      await db.prepare("INSERT INTO org_members(organization_id,user_uid,role,status,created_by,created_at) VALUES(?,?,?,'active',?,CURRENT_TIMESTAMP) ON CONFLICT(organization_id,user_uid) DO UPDATE SET role=excluded.role,status='active',created_by=excluded.created_by").bind(orgId,target.uid,role,user.uid).run();
      await audit(db,user,'workspace.member_added','workspace_member',target.uid,orgId);
      return reply({added:true,member:{uid:target.uid,email,displayName:target.display_name||'',role,status:'active'}},201);
    }
    if(method==='DELETE'){
      const uid=url.searchParams.get('uid');if(!uid)fail(400,'MEMBER_UID_REQUIRED','uid is required.');
      const member=await db.prepare('SELECT role FROM org_members WHERE organization_id=? AND user_uid=? LIMIT 1').bind(orgId,uid).first();
      if(!member)fail(404,'MEMBER_NOT_FOUND','Workspace member was not found.');
      if(member.role==='owner'||uid===user.uid)fail(403,'OWNER_PROTECTED','The workspace owner cannot be removed.');
      await db.prepare("UPDATE org_members SET status='revoked' WHERE organization_id=? AND user_uid=?").bind(orgId,uid).run();
      await audit(db,user,'workspace.member_revoked','workspace_member',uid,orgId);
      return reply({revoked:true,uid});
    }
    return methodDenied(['GET','POST','DELETE']);
  }
  if(path==='/api/admin/mcp-tokens'){
    const user=await requireUser(request,env);requireOwner(user,env);
    const orgId=url.searchParams.get('organizationId');if(!orgId)fail(400,'ORGANIZATION_ID_REQUIRED','organizationId is required.');
    await orgAccess(db,user.uid,orgId,ADMIN);
    if(method==='GET'){
      const rows=await db.prepare('SELECT id,label,project_id,expires_at,last_used_at,status,created_at,revoked_at FROM mcp_tokens WHERE organization_id=? ORDER BY created_at DESC LIMIT 100').bind(orgId).all();
      return reply({endpoint:new URL('/mcp',request.url).toString(),readOnly:true,defaultExpiryDays:90,tokens:rows.results||[]});
    }
    if(method==='POST'){
      const body=await bodyJson(request,16384),label=textValue(body.label,'Token label',80),projectId=body.projectId?idValue(body.projectId,'projectId'):null;
      if(projectId)await projectAccess(db,user.uid,orgId,projectId,ADMIN);
      let days=Number.isInteger(body.expiresInDays)?body.expiresInDays:90;if(days<7||days>90)fail(400,'INVALID_EXPIRY','MCP read tokens must expire in 7 to 90 days.');
      const secret='ajnxt_mcp_'+randomSecret(),hash=await hashValue(secret),id=crypto.randomUUID(),expires=new Date(Date.now()+days*86400000).toISOString().replace('T',' ').slice(0,19);
      await db.prepare("INSERT INTO mcp_tokens(id,token_hash,label,organization_id,project_id,owner_uid,status,expires_at,created_by,created_at) VALUES(?,?,?,?,?,?,'active',?,?,CURRENT_TIMESTAMP)").bind(id,hash,label,orgId,projectId,user.uid,expires,user.uid).run();
      await audit(db,user,'mcp_token.created','mcp_token',id,orgId);
      return reply({created:true,token:secret,tokenId:id,label,organizationId:orgId,projectId,endpoint:new URL('/mcp',request.url).toString(),expiresAt:expires,access:'READ_ONLY',warning:'Copy now; token is only shown once and cannot change, publish or delete data.'},201);
    }
    if(method==='DELETE'){
      const id=url.searchParams.get('id');if(!id)fail(400,'TOKEN_ID_REQUIRED','id is required.');
      const token=await db.prepare("SELECT id,status FROM mcp_tokens WHERE id=? AND organization_id=? LIMIT 1").bind(id,orgId).first();
      if(!token||token.status!=='active')fail(404,'TOKEN_NOT_FOUND','Active token was not found.');
      await db.batch([
        db.prepare("UPDATE mcp_tokens SET status='revoked',revoked_at=CURRENT_TIMESTAMP WHERE id=?").bind(id),
        db.prepare("UPDATE oauth_refresh_tokens SET status='revoked',revoked_at=CURRENT_TIMESTAMP WHERE family_id=? AND status='active'").bind(id)
      ]);
      await audit(db,user,'mcp_token.revoked','mcp_token',id,orgId);return reply({revoked:true,tokenId:id});
    }
    return methodDenied(['GET','POST','DELETE']);
  }
  if(path==='/api/admin/oauth-clients'){
    const user=await requireUser(request,env);requireOwner(user,env);
    if(method==='GET'){
      const rows=await db.prepare('SELECT client_id,client_name,redirect_uris_json,token_endpoint_auth_method,status,created_at,last_used_at,revoked_at FROM oauth_clients ORDER BY created_at DESC LIMIT 200').all();
      return reply({clients:(rows.results||[]).map(c=>({clientId:c.client_id,name:c.client_name,redirectUris:(()=>{try{return JSON.parse(c.redirect_uris_json||'[]')}catch{return []}})(),tokenEndpointAuthMethod:c.token_endpoint_auth_method,status:c.status,createdAt:c.created_at,lastUsedAt:c.last_used_at||null,revokedAt:c.revoked_at||null})),note:'Revoking a client also revokes its access-token families and refresh tokens.'});
    }
    if(method==='DELETE'){
      const clientId=url.searchParams.get('clientId');
      if(!clientId)fail(400,'CLIENT_ID_REQUIRED','clientId is required.');
      const client=await db.prepare('SELECT client_id,status FROM oauth_clients WHERE client_id=? LIMIT 1').bind(clientId).first();
      if(!client||client.status!=='active')fail(404,'OAUTH_CLIENT_NOT_FOUND','Active OAuth client was not found.');
      await db.batch([
        db.prepare("UPDATE oauth_clients SET status='revoked',revoked_at=CURRENT_TIMESTAMP WHERE client_id=?").bind(clientId),
        db.prepare("UPDATE mcp_tokens SET status='revoked',revoked_at=CURRENT_TIMESTAMP WHERE id IN (SELECT DISTINCT family_id FROM oauth_refresh_tokens WHERE client_id=?)").bind(clientId),
        db.prepare("UPDATE oauth_refresh_tokens SET status='revoked',revoked_at=CURRENT_TIMESTAMP WHERE client_id=? AND status='active'").bind(clientId)
      ]);
      await audit(db,user,'oauth_client.revoked','oauth_client',clientId);
      return reply({revoked:true,clientId});
    }
    return methodDenied(['GET','DELETE']);
  }

  if(path==='/api/admin/retention'){
    const user=await requireUser(request,env);requireOwner(user,env);
    if(method!=='GET')return methodDenied(['GET']);
    const rows=await db.prepare("SELECT id,started_at,finished_at,deleted_metrics,deleted_sales,deleted_costs,deleted_reports,deleted_drafts,deleted_scheduled_posts,deleted_audit_events,deleted_expired_mcp_tokens,status,error_code FROM retention_runs ORDER BY started_at DESC LIMIT 30").all();
    return reply({retentionDays:RETENTION_DAYS,schedule:'Daily at 02:17 UTC',lastRuns:rows.results||[],policy:'Old imported analytics/financial records, drafts, old scheduled posts, reports, audit events and expired/revoked MCP tokens are purged. Account/workspace/project and active connection configuration is retained.'});
  }

  const integrationsRoute=path.match(/^\/api\/projects\/([A-Za-z0-9_-]+)\/integrations$/);
  if(integrationsRoute){
    const user=await requireUser(request,env),projectId=integrationsRoute[1],orgId=url.searchParams.get('organizationId');
    if(!orgId)fail(400,'ORGANIZATION_ID_REQUIRED','organizationId is required.');
    await projectAccess(db,user.uid,orgId,projectId,method==='GET'?READ:WRITE);
    if(method==='GET'){
      const rows=await db.prepare('SELECT id,provider,account_id,account_name,status,scopes_json,last_verified_at,last_sync_at,created_at,updated_at FROM integration_connections WHERE organization_id=? AND project_id=? ORDER BY provider').bind(orgId,projectId).all();
      return reply({projectId,connections:(rows.results||[]).map(r=>({id:r.id,provider:r.provider,accountId:r.account_id||null,accountName:r.account_name||null,status:r.status,scopes:(()=>{try{return JSON.parse(r.scopes_json||'[]')}catch{return []}})(),lastVerifiedAt:r.last_verified_at||null,lastSyncAt:r.last_sync_at||null,updatedAt:r.updated_at||null})),note:'Only a successful official authorization/API check should be labelled connected.'});
    }
    if(method==='POST'){
      const body=await bodyJson(request,16384);
      if(body.organizationId!==orgId)fail(400,'ORGANIZATION_SCOPE_MISMATCH','Workspace does not match URL.');
      const provider=textValue(body.provider,'Provider',80).toLowerCase().replace(/\s+/g,'_');
      const status=textValue(body.status||'not_connected','Status',40);
      if(!/^[a-z][a-z0-9_]{0,79}$/.test(provider))fail(400,'INVALID_PROVIDER','Provider name is invalid.');
      if(!['not_connected','import_required','revoked'].includes(status))fail(400,'UNVERIFIED_CONNECT_STATUS','Manual status changes cannot mark an account connected or pending. Only a verified OAuth flow may do that.');
      const prior=await db.prepare('SELECT id FROM integration_connections WHERE organization_id=? AND project_id=? AND provider=? AND account_id IS NULL LIMIT 1').bind(orgId,projectId,provider).first();
      if(prior)await db.prepare("UPDATE integration_connections SET status=?,updated_at=CURRENT_TIMESTAMP,account_name=NULL,scopes_json='[]',last_verified_at=NULL,last_sync_at=NULL WHERE id=? AND organization_id=? AND project_id=?").bind(status,prior.id,orgId,projectId).run();
      else await db.prepare("INSERT INTO integration_connections(id,organization_id,project_id,provider,account_name,status,scopes_json,created_by,created_at,updated_at) VALUES(?,?,?,?,'',?,'[]',?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)").bind(crypto.randomUUID(),orgId,projectId,provider,status,user.uid).run();
      await audit(db,user,'integration.status_changed','integration_connection',provider,orgId);
      return reply({updated:true,provider,status,connected:false,message:'Saved an import/disconnect note only. No external account was connected.'});
    }
    return methodDenied(['GET','POST']);
  }

  const detail=path.match(/^\/api\/projects\/([A-Za-z0-9_-]+)$/);
  if(detail){
    const user=await requireUser(request,env),projectId=detail[1],orgId=url.searchParams.get('organizationId');
    if(!orgId)fail(400,'ORGANIZATION_ID_REQUIRED','organizationId is required.');
    const access=await projectAccess(db,user.uid,orgId,projectId,ADMIN);
    if(method==='PATCH'){
      const body=await bodyJson(request,16384),name=textValue(body.name,'Project name',90),type=textValue(body.type||access.project.type||'Other','Project type',60),location=textValue(body.location===undefined?(access.project.location||''):body.location,'Project location',120,false);
      if(await db.prepare("SELECT id FROM projects WHERE organization_id=? AND name_lower=? AND status='active' AND id<>? LIMIT 1").bind(orgId,name.toLowerCase(),projectId).first())fail(409,'PROJECT_NAME_EXISTS','Another active project uses this name.');
      await db.batch([
        db.prepare('UPDATE projects SET name=?,name_lower=?,type=?,location=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND organization_id=?').bind(name,name.toLowerCase(),type,location,projectId,orgId),
        db.prepare("INSERT INTO audit_events(id,organization_id,actor_uid,action,resource_type,resource_id,created_at) VALUES(?,?,?,'project.updated','project',?,CURRENT_TIMESTAMP)").bind(crypto.randomUUID(),orgId,user.uid,projectId)
      ]);
      return reply({project:{id:projectId,name,type,location,status:'active'}});
    }
    if(method==='DELETE'){
      await db.batch([
        db.prepare("UPDATE projects SET status='archived',updated_at=CURRENT_TIMESTAMP WHERE id=? AND organization_id=? AND status='active'").bind(projectId,orgId),
        db.prepare("INSERT INTO audit_events(id,organization_id,actor_uid,action,resource_type,resource_id,created_at) VALUES(?,?,?,'project.archived','project',?,CURRENT_TIMESTAMP)").bind(crypto.randomUUID(),orgId,user.uid,projectId)
      ]);return reply({archived:true,projectId});
    }
    return methodDenied(['PATCH','DELETE']);
  }
  const projectRoute=path.match(/^\/api\/projects\/([A-Za-z0-9_-]+)\/(metrics|imports|reports|drafts|sales|costs|financial-report)$/);
  if(projectRoute){
    const user=await requireUser(request,env),projectId=projectRoute[1],kind=projectRoute[2],orgId=url.searchParams.get('organizationId');
    if(!orgId)fail(400,'ORGANIZATION_ID_REQUIRED','organizationId is required.');
    const access=await projectAccess(db,user.uid,orgId,projectId,kind==='imports'||kind==='drafts'||kind==='sales'||kind==='costs'?WRITE:READ);
    const range=dateRange(url.searchParams);
    if(kind==='metrics'){
      if(method!=='GET')return methodDenied(['GET']);
      let limit=Number.parseInt(url.searchParams.get('limit')||'500',10);if(!Number.isFinite(limit)||limit<1)limit=500;limit=Math.min(limit,1000);
      const rows=await metricRows(db,projectId,range.start,range.end,limit);
      return reply({organizationId:orgId,projectId,projectName:access.project.name,count:rows.length,metrics:rows.map(metricOut),note:'Imported values are not independently verified by this API.'});
    }
    if(kind==='imports'){
      if(method!=='POST')return methodDenied(['POST']);
      const body=await bodyJson(request,262144);
      if(body.organizationId!==orgId)fail(400,'ORGANIZATION_SCOPE_MISMATCH','Request organization does not match URL.');
      if(!Array.isArray(body.records)||body.records.length<1||body.records.length>80)fail(400,'INVALID_RECORD_COUNT','Import 1 to 80 observations per request.');
      const records=body.records.map((r,i)=>{
        if(!r||typeof r!=='object'||Array.isArray(r)||!validDate(r.date))fail(400,'INVALID_METRIC_RECORD','Record '+(i+1)+' needs a valid date.');
        const platform=textValue(r.platform,'Platform',60),metric=textValue(r.metric,'Metric',64).toLowerCase().replace(/\s+/g,'_');
        if(!/^[a-z][a-z0-9_]{0,63}$/.test(metric))fail(400,'INVALID_METRIC','Metric name has invalid characters.');
        const value=typeof r.value==='number'?r.value:Number(r.value);if(!Number.isFinite(value)||value<0||value>1e15)fail(400,'INVALID_METRIC_VALUE','Metric value must be finite and non-negative.');
        return {date:r.date,platform,platformKey:platform.toLowerCase(),metric,metricKey:metric.toLowerCase(),value,source:textValue(r.source||'User CSV import','Source',160)};
      });
      const seen=new Set();for(const r of records){const key=[r.date,r.platformKey,r.metricKey].join('|');if(seen.has(key))fail(409,'DUPLICATE_INPUT_RECORD','Import contains duplicate date/platform/metric records.');seen.add(key);}
      const earliest=records.reduce((m,r)=>r.date<m?r.date:m,records[0].date),latest=records.reduce((m,r)=>r.date>m?r.date:m,records[0].date);
      const previous=await db.prepare('SELECT date,platform_key,metric_key FROM metrics WHERE project_id=? AND date>=? AND date<=? LIMIT 20000').bind(projectId,earliest,latest).all();
      const old=new Set((previous.results||[]).map(r=>[r.date,r.platform_key,r.metric_key].join('|')));
      for(const r of records)if(old.has([r.date,r.platformKey,r.metricKey].join('|')))fail(409,'DUPLICATE_STORED_RECORD','Duplicate observations are not overwritten.');
      const inserts=[];
      for(const r of records){const id=await hashValue([projectId,r.date,r.platformKey,r.metricKey].join('|'));inserts.push(db.prepare("INSERT INTO metrics(id,organization_id,project_id,date,platform,platform_key,metric,metric_key,value,source,source_verified,imported_by,imported_at) VALUES(?,?,?,?,?,?,?,?,?,?,0,?,CURRENT_TIMESTAMP)").bind(id,orgId,projectId,r.date,r.platform,r.platformKey,r.metric,r.metricKey,r.value,r.source,user.uid));}
      inserts.push(db.prepare("INSERT INTO audit_events(id,organization_id,actor_uid,action,resource_type,resource_id,record_count,created_at) VALUES(?,?,?,'metrics.imported','project',?,?,CURRENT_TIMESTAMP)").bind(crypto.randomUUID(),orgId,user.uid,projectId,records.length));
      try{await db.batch(inserts);}catch(e){if(String(e&&e.message||'').includes('UNIQUE constraint failed'))fail(409,'IMPORT_CONFLICT','A duplicate observation exists; no records were intentionally overwritten.');throw e;}
      return reply({imported:records.length,projectId,organizationId:orgId,sourceVerified:false},201);
    }
    if(kind==='reports'){
      if(method!=='GET')return methodDenied(['GET']);
      let limit=Number.parseInt(url.searchParams.get('limit')||'2000',10);if(!Number.isFinite(limit)||limit<1)limit=2000;limit=Math.min(limit,2000);
      const rows=await metricRows(db,projectId,range.start,range.end,limit),analytics=analyticsFor(rows.slice().reverse());
      return reply({project:{id:projectId,name:access.project.name},generatedAt:new Date().toISOString(),recordCount:rows.length,dataCoverage:{firstDate:rows.length?rows.reduce((m,r)=>r.date<m?r.date:m,rows[0].date):null,latestDate:rows.length?rows.reduce((m,r)=>r.date>m?r.date:m,rows[0].date):null,limitApplied:rows.length===limit},...analytics,records:rows.map(metricOut),disclaimers:['Imports are unverified by default.','Missing dates are never zero.','Forecasts are estimates, not promises.','Revenue is not profit without complete, validated costs.']});
    }
    if(kind==='drafts'){
      const draftId=path.match(/^\/api\/projects\/[A-Za-z0-9_-]+\/drafts\/([A-Za-z0-9_-]+)$/)?.[1]||null;
      if(method==='GET'&&!draftId){
        const rows=await db.prepare("SELECT id,title,copy_text,platforms_json,status,created_by,created_at,updated_at FROM content_drafts WHERE organization_id=? AND project_id=? AND status<>'archived' ORDER BY updated_at DESC LIMIT 300").bind(orgId,projectId).all();
        return reply({drafts:(rows.results||[]).map(d=>({id:d.id,title:d.title,copy:d.copy_text,platforms:JSON.parse(d.platforms_json||'[]'),platform:(JSON.parse(d.platforms_json||'[]')[0]||'Instagram'),status:d.status,createdBy:d.created_by,createdAt:d.created_at,updatedAt:d.updated_at,published:false}))});
      }
      if(method==='POST'&&!draftId){
        const body=await bodyJson(request,32768);if(body.organizationId!==orgId)fail(400,'ORGANIZATION_SCOPE_MISMATCH','Request organization does not match URL.');
        const title=textValue(body.title,'Draft title',160),copy=textValue(body.copy||'','Draft copy',10000,false),platform=textValue(body.platform||'Instagram','Platform',60),id=crypto.randomUUID();
        await db.batch([
          db.prepare("INSERT INTO content_drafts(id,organization_id,project_id,title,copy_text,platforms_json,media_refs_json,status,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,'[]','draft',?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)").bind(id,orgId,projectId,title,copy,JSON.stringify([platform]),user.uid),
          db.prepare("INSERT INTO audit_events(id,organization_id,actor_uid,action,resource_type,resource_id,created_at) VALUES(?,?,?,'draft.created','content_draft',?,CURRENT_TIMESTAMP)").bind(crypto.randomUUID(),orgId,user.uid,id)
        ]);
        return reply({draft:{id,title,copy,platform,platforms:[platform],status:'draft',createdAt:new Date().toISOString()},published:false},201);
      }
      if(method==='DELETE'&&draftId){
        const old=await db.prepare("SELECT id FROM content_drafts WHERE id=? AND organization_id=? AND project_id=? AND status<>'archived' LIMIT 1").bind(draftId,orgId,projectId).first();
        if(!old)fail(404,'DRAFT_NOT_FOUND','Draft was not found.');
        await db.batch([
          db.prepare("UPDATE content_drafts SET status='archived',updated_at=CURRENT_TIMESTAMP WHERE id=? AND organization_id=? AND project_id=?").bind(draftId,orgId,projectId),
          db.prepare("INSERT INTO audit_events(id,organization_id,actor_uid,action,resource_type,resource_id,created_at) VALUES(?,?,?,'draft.archived','content_draft',?,CURRENT_TIMESTAMP)").bind(crypto.randomUUID(),orgId,user.uid,draftId)
        ]);return reply({archived:true,draftId});
      }
      return methodDenied(draftId?['DELETE']:['GET','POST']);
    }
    if(kind==='sales'){
      if(method==='GET'){
        let sql='SELECT id,date,source,metric,value,currency,source_verified,imported_at FROM sales_observations WHERE project_id=?',args=[projectId];if(range.start){sql+=' AND date>=?';args.push(range.start);}if(range.end){sql+=' AND date<=?';args.push(range.end);}sql+=' ORDER BY date DESC LIMIT 3000';const r=await db.prepare(sql).bind(...args).all();return reply({observations:r.results||[]});
      }
      if(method!=='POST')return methodDenied(['GET','POST']);
      const body=await bodyJson(request,131072);if(body.organizationId!==orgId||!Array.isArray(body.records)||body.records.length<1||body.records.length>80)fail(400,'INVALID_SALES_BATCH','Provide matching organizationId and 1–80 sales rows.');
      const records=body.records.map((r,i)=>{if(!r||!validDate(r.date))fail(400,'INVALID_SALES_RECORD','Sales row '+(i+1)+' needs a valid date.');const source=textValue(r.source,'Source',100),metric=textValue(r.metric||'revenue','Metric',40).toLowerCase(),value=Number(r.value),currency=textValue(r.currency||'INR','Currency',3).toUpperCase();if(!['revenue','orders','refunds','discounts'].includes(metric)||!Number.isFinite(value)||value<0||!/^[A-Z]{3}$/.test(currency))fail(400,'INVALID_SALES_RECORD','Sales rows need an allowed metric and non-negative value.');return {date:r.date,source,metric,value,currency};});
      const keys=new Set();for(const r of records){const key=[r.date,r.source.toLowerCase(),r.metric,r.currency].join('|');if(keys.has(key))fail(409,'DUPLICATE_INPUT_RECORD','Duplicate source/metric/date rows in request.');keys.add(key);}
      const stmts=records.map(r=>db.prepare("INSERT INTO sales_observations(id,organization_id,project_id,date,source,metric,value,currency,source_verified,imported_by,imported_at) VALUES(?,?,?,?,?,?,?,?,0,?,CURRENT_TIMESTAMP)").bind(crypto.randomUUID(),orgId,projectId,r.date,r.source,r.metric,r.value,r.currency,user.uid));
      stmts.push(db.prepare("INSERT INTO audit_events(id,organization_id,actor_uid,action,resource_type,resource_id,record_count,created_at) VALUES(?,?,?,'sales.imported','project',?,?,CURRENT_TIMESTAMP)").bind(crypto.randomUUID(),orgId,user.uid,projectId,records.length));
      try{await db.batch(stmts);}catch(e){if(String(e&&e.message||'').includes('UNIQUE constraint failed'))fail(409,'DUPLICATE_STORED_RECORD','Duplicate sales rows are not overwritten.');throw e;}
      return reply({imported:records.length,sourceVerified:false},201);
    }
    if(kind==='costs'){
      if(method==='GET'){let sql='SELECT id,date,category,amount,currency,description,source,created_at FROM business_costs WHERE project_id=?',args=[projectId];if(range.start){sql+=' AND date>=?';args.push(range.start);}if(range.end){sql+=' AND date<=?';args.push(range.end);}sql+=' ORDER BY date DESC LIMIT 3000';const r=await db.prepare(sql).bind(...args).all();return reply({costs:r.results||[]});}
      if(method!=='POST')return methodDenied(['GET','POST']);
      const body=await bodyJson(request,131072);if(body.organizationId!==orgId||!Array.isArray(body.records)||body.records.length<1||body.records.length>80)fail(400,'INVALID_COST_BATCH','Provide matching organizationId and 1–80 cost rows.');
      const records=body.records.map((r,i)=>{if(!r||!validDate(r.date))fail(400,'INVALID_COST_RECORD','Cost row '+(i+1)+' needs a valid date.');const category=textValue(r.category,'Category',100),amount=Number(r.amount),currency=textValue(r.currency||'INR','Currency',3).toUpperCase(),description=textValue(r.description||'','Description',300,false),source=textValue(r.source||'User entry','Source',100);if(!Number.isFinite(amount)||amount<0||!/^[A-Z]{3}$/.test(currency))fail(400,'INVALID_COST_RECORD','Cost amount must be non-negative and currency valid.');return {date:r.date,category,amount,currency,description,source};});
      const stmts=records.map(r=>db.prepare("INSERT INTO business_costs(id,organization_id,project_id,date,category,amount,currency,description,source,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)").bind(crypto.randomUUID(),orgId,projectId,r.date,r.category,r.amount,r.currency,r.description,r.source,user.uid));
      stmts.push(db.prepare("INSERT INTO audit_events(id,organization_id,actor_uid,action,resource_type,resource_id,record_count,created_at) VALUES(?,?,?,'costs.entered','project',?,?,CURRENT_TIMESTAMP)").bind(crypto.randomUUID(),orgId,user.uid,projectId,records.length));
      await db.batch(stmts);return reply({saved:records.length,sourceVerified:false},201);
    }
    if(kind==='financial-report'){
      if(method!=='GET')return methodDenied(['GET']);
      return reply({project:{id:projectId,name:access.project.name},organizationId:orgId,period:range,totals:await readFinancial(db,projectId,range.start,range.end),disclaimers:['This is an entered-record reconciliation, not audited results.','Revenue minus recorded costs is not net profit.','Manual/imported records are unverified by default.','Currencies are grouped separately.']});
    }
  }
  if(path==='/api/admin/mcp-tokens'){
    const user=await requireUser(request,env);requireOwner(user,env);const orgId=url.searchParams.get('organizationId');if(!orgId)fail(400,'ORGANIZATION_ID_REQUIRED','organizationId is required.');await orgAccess(db,user.uid,orgId,ADMIN);
    if(method==='GET'){const r=await db.prepare('SELECT id,label,project_id,expires_at,last_used_at,status,created_at,revoked_at FROM mcp_tokens WHERE organization_id=? ORDER BY created_at DESC LIMIT 100').bind(orgId).all();return reply({endpoint:new URL('/mcp',request.url).toString(),readOnly:true,defaultExpiryDays:90,tokens:r.results||[]});}
    if(method==='POST'){const body=await bodyJson(request,16384),label=textValue(body.label,'Token label',80),projectId=body.projectId?idValue(body.projectId,'projectId'):null;if(projectId)await projectAccess(db,user.uid,orgId,projectId,ADMIN);const days=Number.isInteger(body.expiresInDays)?body.expiresInDays:90;if(days<7||days>90)fail(400,'INVALID_EXPIRY','MCP tokens must expire in 7–90 days.');const secret='ajnxt_mcp_'+randomSecret(),hash=await hashValue(secret),id=crypto.randomUUID(),expires=new Date(Date.now()+days*86400000).toISOString().replace('T',' ').slice(0,19);await db.prepare("INSERT INTO mcp_tokens(id,token_hash,label,organization_id,project_id,owner_uid,status,expires_at,created_by,created_at) VALUES(?,?,?,?,?,?,'active',?,?,CURRENT_TIMESTAMP)").bind(id,hash,label,orgId,projectId,user.uid,expires,user.uid).run();await audit(db,user,'mcp_token.created','mcp_token',id,orgId);return reply({created:true,token:secret,tokenId:id,label,organizationId:orgId,projectId,endpoint:new URL('/mcp',request.url).toString(),expiresAt:expires,access:'READ_ONLY',warning:'Token is shown once; it cannot change, publish or delete data.'},201);}
    if(method==='DELETE'){const id=url.searchParams.get('id');if(!id)fail(400,'TOKEN_ID_REQUIRED','id is required.');const t=await db.prepare("SELECT id,status FROM mcp_tokens WHERE id=? AND organization_id=?").bind(id,orgId).first();if(!t||t.status!=='active')fail(404,'TOKEN_NOT_FOUND','Active MCP token not found.');await db.batch([db.prepare("UPDATE mcp_tokens SET status='revoked',revoked_at=CURRENT_TIMESTAMP WHERE id=?").bind(id),db.prepare("UPDATE oauth_refresh_tokens SET status='revoked',revoked_at=CURRENT_TIMESTAMP WHERE family_id=? AND status='active'").bind(id)]);await audit(db,user,'mcp_token.revoked','mcp_token',id,orgId);return reply({revoked:true,tokenId:id});}
    return methodDenied(['GET','POST','DELETE']);
  }
  if(path==='/api/admin/retention'){
    const user=await requireUser(request,env);requireOwner(user,env);if(method!=='GET')return methodDenied(['GET']);
    const rows=await db.prepare("SELECT id,started_at,finished_at,deleted_metrics,deleted_sales,deleted_costs,deleted_reports,deleted_drafts,deleted_scheduled_posts,deleted_audit_events,deleted_expired_mcp_tokens,status,error_code FROM retention_runs ORDER BY started_at DESC LIMIT 30").all();
    return reply({retentionDays:365,schedule:'Daily at 02:17 UTC',lastRuns:rows.results||[],note:'Old reportable records are purged; workspace, project, user and active connection configuration is retained.'});
  }
  if(path==='/api/admin/retention/run'){
    const user=await requireUser(request,env);requireOwner(user,env);if(method!=='POST')return methodDenied(['POST']);const result=await runRetention(env);return reply({triggered:true,...result});
  }
  return reply({error:'NOT_FOUND',message:'Endpoint not found.'},404);
}
export default {
  async fetch(request,env){
    if(!new URL(request.url).pathname.startsWith('/api/')&&!new URL(request.url).pathname.startsWith('/mcp')&&!new URL(request.url).pathname.startsWith('/oauth/')&&!new URL(request.url).pathname.startsWith('/.well-known/')){if(env.ASSETS)return env.ASSETS.fetch(request);return new Response('AJAYNXT Social Hub assets are not configured.',{status:503});}
    try{return await router(request,env);}catch(e){if(e instanceof ApiError)return reply({error:e.code,message:e.message},e.status);console.error('AJAYNXT Worker failure',{name:e&&e.name?String(e.name).slice(0,80):'Error'});return reply({error:'INTERNAL_ERROR',message:'The server could not complete this request.'},500);}
  },
  async scheduled(controller,env,ctx){ctx.waitUntil(runRetention(env).catch(()=>{}));}
};
export { analyticsFor, validDate, requireOwner, mcpToolDefinitions };
