# AJAYNXT Social Hub

Low-cost multi-project social/content and business-reporting workspace. Start with your personal Diamond Restaurant project, then add more client projects and separate access permissions.

## Architecture

- Responsive website + installable Progressive Web App (PWA)
- Cloudflare Workers API and D1 database
- Firebase Authentication for Google sign-in
- Server-verified Super Admin UID, workspace roles and audited access changes
- Social/media/ads/marketplace integration catalogue with official account portal and setup links
- CSV imports, project metrics, complete-window growth comparisons and cautious trend estimates
- Sales/cost entry with currency-separated financial reconciliation (not net profit)
- Draft content stored per project; no social post is marked published until a real provider connector confirms it
- Read-only remote MCP server and OAuth authorization code + PKCE for AI clients
- Scheduled 365-day cleanup for reporting/financial observations, old drafts/reports/audit events, expired OAuth sessions/tokens and old records

No Supabase, Firestore, Firebase Admin SDK or Firebase Cloud Functions are needed in this architecture.

## Deployment status

The code is in GitHub, but the platform is **not yet deployed to the owner's Cloudflare account or connected to the owner's Firebase project**. The D1 placeholder ID in wrangler.jsonc must be replaced by the real ID from Cloudflare. Firebase's web settings, the real owner UID, and the three SQL migrations must be configured/applied before login or scheduled deletion works.

The older Vercel preview is only the static prototype; it does not run this Cloudflare Worker backend. Use [the Cloudflare setup guide](docs/CLOUDFLARE-SETUP.md) for the real deployment route.

## Important feature boundaries

- Account portal links open the official account/dashboard page. They do not automatically authorize AJAYNXT to read data.
- Instagram, Facebook/Threads, YouTube, LinkedIn, TikTok, X, Pinterest, ads, Google Business Profile and other provider APIs need official OAuth, required app review/product access and a successful API test.
- Swiggy and Zomato are labelled Import required until an approved API connection is available and tested. Partner portal links and genuine CSV reports can be used for analysis.
- AI/MCP OAuth can share already-stored data with a scoped AI client. It cannot connect a disconnected provider by itself.
- MCP tools are read-only. They cannot create Admin IDs, change settings, publish content or delete project data.
- Reports are as reliable as their source data. Imported/manual rows are unverified by default. Missing dates are never zero. Forecasts require consecutive data and remain estimates.
- Revenue minus entered costs is not net profit.
- The one-year cleanup follows observation dates for metrics/sales/costs and record timestamps for other reporting data. Workspace/user/login configuration and active connection settings are preserved.

## Setup and usage

1. Follow [Cloudflare setup](docs/CLOUDFLARE-SETUP.md).
2. Configure Firebase Google sign-in and set AJAYNXT_SUPER_ADMIN_UID to your exact Firebase Auth UID as a Cloudflare Worker secret.
3. Create the D1 database, replace the placeholder ID and apply migrations 0001–0003.
4. Deploy Worker assets, sign in at the site, then open /admin.html to create/revoke Admin IDs and manage members.
5. Use Integrations for official login/API links; connect each provider only when its own authorization/API test succeeds.
6. Use the Admin Console AI/MCP panel to read the MCP endpoint/discovery URLs and manage read-only access.
7. Use Admin Console → 365-day data retention to review cleanup history or run owner-authorized cleanup manually.

## Tests

~~~bash
npm install
npm run build
npm run check:syntax
npm test
~~~

Local Worker variables belong in the ignored .dev.vars file copied from .dev.vars.example. Never commit Firebase secrets, Super Admin UID, provider tokens, MCP tokens or OAuth credentials.
