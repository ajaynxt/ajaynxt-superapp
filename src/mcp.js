function rpcJson(svc, body, status=200) {
  return svc.json(body,status);
}

function toolCatalog() {
  const scoped = {
    type:'object',
    properties:{
      organizationId:{type:'string',description:'Workspace ID, unless the access token is scoped to a workspace.'},
      projectId:{type:'string',description:'Project ID, unless the access token is scoped to one project.'},
      startDate:{type:'string',pattern:'^\\d{4}-\\d{2}-\\d{2}$'},
      endDate:{type:'string',pattern:'^\\d{4}-\\d{2}-\\d{2}$'},
      limit:{type:'integer',minimum:1,maximum:1000}
    }
  };
  return [
    {name:'list_workspaces',description:'List only workspaces accessible to the authenticated identity.',inputSchema:{type:'object',properties:{}}},
    {name:'list_projects',description:'List active projects in an authorized workspace.',inputSchema:scoped},
    {name:'get_project_metrics',description:'Read actual imported observations; imported values are unverified unless sourceVerified is true.',inputSchema:scoped},
    {name:'get_growth_report',description:'Read data coverage, complete-window comparisons and eligible seven-day trend estimates.',inputSchema:scoped},
    {name:'list_integrations',description:'Read connection states; a catalogue entry is not a live account connection.',inputSchema:scoped},
    {name:'list_content_drafts',description:'Read project drafts. This tool cannot publish posts.',inputSchema:scoped},
    {name:'get_financial_summary',description:'Read reported sales and entered costs by currency; do not interpret as net profit.',inputSchema:scoped},
    {name:'get_data_retention_policy',description:'Read the 365-day retention rule and exclusions for active access/setup records.',inputSchema:{type:'object',properties:{}}}
  ];
}

async function scopedProject(db, auth, args, svc) {
  const organizationId=auth.organizationId||args.organizationId;
  if(!organizationId)throw new svc.ApiError(400,'ORGANIZATION_ID_REQUIRED','organizationId is required unless the MCP token has a workspace scope.');
  if(auth.organizationId&&args.organizationId&&args.organizationId!==auth.organizationId)throw new svc.ApiError(403,'MCP_SCOPE_DENIED','This token is scoped to a different workspace.');
  const projectId=auth.projectId||args.projectId||null;
  if(auth.projectId&&args.projectId&&args.projectId!==auth.projectId)throw new svc.ApiError(403,'MCP_SCOPE_DENIED','This token is scoped to a different project.');
  if(projectId) {
    const access=await svc.projectAccess(db,auth.uid,organizationId,projectId,svc.ROLE_READ);
    return {organizationId,projectId,project:access.project};
  }
  await svc.orgAccess(db,auth.uid,organizationId,svc.ROLE_READ);
  return {organizationId,projectId:null,project:null};
}

async function callTool(db,auth,name,args,svc) {
  if(name==='get_data_retention_policy')return {
    retentionDays:365,
    dailyCleanupCron:'03:00 UTC',
    removes:['Metrics, sales/cost records and generated reports older than 365 days','Drafts older than 365 days','Published/failed/cancelled post records older than 365 days','Old unconnected/revoked integration metadata, revoked Admin IDs, revoked memberships and audit events'],
    keeps:['Active workspace/project setup and access records','Active connection metadata needed for current integrations','Minimum account identity needed to enforce access','Super Admin UID as an encrypted Worker secret'],
    note:'Automatic deletion only runs after the Worker, D1 migrations and cron are deployed; confirm successful retention_runs before relying on it.'
  };
  if(name==='list_workspaces') {
    if(auth.organizationId){
      const row=await db.prepare("SELECT id,name,created_at FROM organizations WHERE id=? AND status='active' LIMIT 1").bind(auth.organizationId).first();
      return {workspaces:row?[row]:[]};
    }
    const rows=await db.prepare("SELECT o.id,o.name,m.role,o.created_at FROM organizations o JOIN org_members m ON m.organization_id=o.id WHERE m.user_uid=? AND m.status='active' AND o.status='active' ORDER BY o.created_at ASC LIMIT 50").bind(auth.uid).all();
    return {workspaces:rows.results||[]};
  }

  const scope=await scopedProject(db,auth,args,svc);
  if(name==='list_projects') {
    const rows=await db.prepare("SELECT id,name,type,location,status,created_at FROM projects WHERE organization_id=? AND status='active' ORDER BY created_at ASC LIMIT 200").bind(scope.organizationId).all();
    return {organizationId:scope.organizationId,projects:(rows.results||[]).filter(p=>!auth.projectId||p.id===auth.projectId)};
  }
  if(!scope.projectId)throw new svc.ApiError(400,'PROJECT_ID_REQUIRED','projectId is required unless the token is project-scoped.');

  if(name==='get_project_metrics'||name==='get_growth_report') {
    if(args.startDate&&!svc.validDate(args.startDate))throw new svc.ApiError(400,'INVALID_START_DATE','startDate must use YYYY-MM-DD.');
    if(args.endDate&&!svc.validDate(args.endDate))throw new svc.ApiError(400,'INVALID_END_DATE','endDate must use YYYY-MM-DD.');
    if(args.startDate&&args.endDate&&args.startDate>args.endDate)throw new svc.ApiError(400,'INVALID_DATE_RANGE','startDate must be on or before endDate.');
    const cap=name==='get_growth_report'?svc.REPORT_LIMIT:1000;
    const defaultLimit=name==='get_growth_report'?svc.REPORT_LIMIT:500;
    const limit=Math.min(cap,Math.max(1,Number.isInteger(args.limit)?args.limit:defaultLimit));
    const rows=await svc.metricRows(db,scope.projectId,args.startDate,args.endDate,limit);
    if(name==='get_project_metrics')return {project:scope.project,count:rows.length,records:rows.map(svc.metricOut),note:'Imported values are not independently verified unless sourceVerified is true.'};
    const ordered=rows.slice().reverse();
    const analytics=svc.analyticsFor(ordered);
    return {project:scope.project,count:rows.length,dataCoverage:{firstDate:rows.length?rows.reduce((a,r)=>r.date<a?r.date:a,rows[0].date):null,latestDate:rows.length?rows.reduce((a,r)=>r.date>a?r.date:a,rows[0].date):null},...analytics,disclaimers:['Imported rows remain unverified until reconciled with source.','Missing dates are not zero.','Forecasts are estimates, not guarantees.']};
  }
  if(name==='list_integrations') {
    const rows=await db.prepare('SELECT provider,account_id,account_name,status,scopes_json,last_verified_at,last_sync_at,updated_at FROM integration_connections WHERE organization_id=? AND project_id=? ORDER BY provider').bind(scope.organizationId,scope.projectId).all();
    return {project:scope.project,connections:(rows.results||[]).map(r=>({provider:r.provider,accountName:r.account_name||null,status:r.status,scopes:(()=>{try{return JSON.parse(r.scopes_json||'[]')}catch{return []}})(),lastVerifiedAt:r.last_verified_at||null,lastSyncAt:r.last_sync_at||null,updatedAt:r.updated_at||null})),note:'Integration catalogue entries do not prove an account is connected.'};
  }
  if(name==='list_content_drafts') {
    const rows=await db.prepare("SELECT id,title,copy_text,platforms_json,status,created_at,updated_at FROM content_drafts WHERE organization_id=? AND project_id=? AND status<>'archived' ORDER BY updated_at DESC LIMIT 300").bind(scope.organizationId,scope.projectId).all();
    return {project:scope.project,drafts:(rows.results||[]).map(d=>({id:d.id,title:d.title,copy:d.copy_text,platforms:(()=>{try{return JSON.parse(d.platforms_json||'[]')}catch{return []}})(),status:d.status,createdAt:d.created_at,updatedAt:d.updated_at})),note:'Drafts only; no publishing actions are available through MCP.'};
  }
  if(name==='get_financial_summary') {
    const [sales,costs]=await Promise.all([
      db.prepare("SELECT currency,SUM(value) AS total,COUNT(*) AS rows FROM sales_observations WHERE organization_id=? AND project_id=? AND metric='revenue' GROUP BY currency").bind(scope.organizationId,scope.projectId).all(),
      db.prepare('SELECT currency,SUM(amount) AS total,COUNT(*) AS rows FROM business_costs WHERE organization_id=? AND project_id=? GROUP BY currency').bind(scope.organizationId,scope.projectId).all()
    ]);
    const totals=new Map();
    for(const r of sales.results||[])totals.set(r.currency,{currency:r.currency,reportedRevenue:Number(r.total||0),revenueRows:r.rows,recordedCosts:0,costRows:0});
    for(const r of costs.results||[]){const v=totals.get(r.currency)||{currency:r.currency,reportedRevenue:0,revenueRows:0,recordedCosts:0,costRows:0};v.recordedCosts=Number(r.total||0);v.costRows=r.rows;totals.set(r.currency,v);}
    return {project:scope.project,totals:Array.from(totals.values()).map(v=>({...v,revenueMinusRecordedCosts:v.reportedRevenue-v.recordedCosts,label:'Revenue minus entered costs — NOT net profit',sourceVerified:false})),disclaimers:['Manual/imported entries are not independently verified.','Missing expenses, taxes, refunds or commissions may make this incomplete.']};
  }
  throw new svc.ApiError(404,'MCP_TOOL_NOT_FOUND','Read-only tool not found.');
}

export async function handleMcp(request,env,svc) {
  if(request.method!=='POST')return svc.methodNotAllowed(['POST']);
  const accept=request.headers.get('Accept')||'';
  if(accept&&(!accept.includes('application/json')||!accept.includes('text/event-stream')))return svc.json({error:'MCP_ACCEPT_REQUIRED',message:'Send Accept: application/json, text/event-stream.'},406);
  const version=request.headers.get('MCP-Protocol-Version');
  if(version&&!['2025-11-25','2025-03-26'].includes(version))return svc.json({error:'MCP_VERSION_UNSUPPORTED',message:'Use MCP protocol version 2025-11-25 or 2025-03-26.'},400);
  let auth;
  try { auth=await svc.resolveMcpAuth(request,env); }
  catch(error) { const status=error.statusCode||error.status||401; return svc.json({error:error.code||'MCP_AUTH_REQUIRED',message:error.message||'A valid read token is required.'},status,{'WWW-Authenticate':'Bearer realm="AJAYNXT Social Hub MCP"'}); }
  let body;
  try { body=await svc.parseBody(request,256*1024); }
  catch(error) { return svc.json({jsonrpc:'2.0',id:null,error:{code:-32700,message:'Invalid JSON body.'}},400); }
  if(body.jsonrpc!=='2.0'||typeof body.method!=='string')return svc.json({jsonrpc:'2.0',id:body.id??null,error:{code:-32600,message:'Invalid JSON-RPC request.'}},400);
  if(body.method.startsWith('notifications/'))return new Response(null,{status:202,headers:{'Cache-Control':'no-store'}});
  const id=body.id??null;
  try {
    if(body.method==='initialize')return svc.json({jsonrpc:'2.0',id,result:{protocolVersion:'2025-11-25',capabilities:{tools:{listChanged:false}},serverInfo:{name:'AJAYNXT Social Hub Read-only MCP',version:'0.1.0'},instructions:'Read-only access to authorized AJAYNXT workspaces. Tools cannot create, change, publish or delete business data.'}});
    if(body.method==='ping')return svc.json({jsonrpc:'2.0',id,result:{}});
    if(body.method==='tools/list')return svc.json({jsonrpc:'2.0',id,result:{tools:toolCatalog()}});
    if(body.method==='tools/call'){
      const params=body.params||{};
      if(typeof params.name!=='string')return svc.json({jsonrpc:'2.0',id,error:{code:-32602,message:'Tool name required.'}},400);
      try {
        const data=await callTool(env.DB,auth,params.name,params.arguments||{},svc);
        return svc.json({jsonrpc:'2.0',id,result:{content:[{type:'text',text:JSON.stringify(data)}],structuredContent:data,isError:false}});
      } catch(error) {
        return svc.json({jsonrpc:'2.0',id,result:{content:[{type:'text',text:JSON.stringify({error:error.code||'TOOL_ERROR',message:error.message||'Tool failed.'})}],isError:true}});
      }
    }
    return svc.json({jsonrpc:'2.0',id,error:{code:-32601,message:'Method not found.'}},404);
  } catch(error) {
    return svc.json({jsonrpc:'2.0',id,error:{code:-32603,message:'Internal MCP error.'}},500);
  }
}
