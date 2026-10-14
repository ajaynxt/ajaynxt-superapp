# AJAYNXT Social Hub — low-cost deployment

## Architecture

The app uses Cloudflare Workers for APIs, Cloudflare D1 for shared data, and Firebase Authentication only for Google sign-in. No Supabase, Firebase Firestore, Firebase Admin SDK or Firebase Cloud Functions are required.

This can start at ₹0 while use remains inside free quotas. Current published limits include up to 100,000 Workers requests/day and D1 Free limits of 5 million rows read/day, 100,000 rows written/day and 5 GB total D1 storage, with a 500 MB maximum per free database. These are real limits, not unlimited scale. Check official pricing/limits before launch:
- https://developers.cloudflare.com/workers/platform/limits/
- https://developers.cloudflare.com/d1/platform/pricing/
- https://firebase.google.com/docs/projects/billing/firebase-pricing-plans

Vercel Hobby is currently for personal, non-commercial use, so the older Vercel preview is not the production target for a future client/agency service:
- https://vercel.com/legal/terms

Do not enable paid services until their price and need are clear.

## Included in this repository

- Cloudflare Worker API with Firebase ID token validation.
- D1 database schema for organizations, memberships, projects, metric imports, draft content, sales, costs, integrations metadata, scheduled-post placeholders, reports and audit events.
- Project-scoped API authorization.
- Server-side Super Admin UID enforcement; only this UID can create or revoke platform Admin IDs.
- Admin Console at /admin.html.
- Financial reconciliation labelled revenue minus entered costs, NOT net profit.
- Installable PWA shell. Native app-store binaries are not built yet.

This is committed code, not a connected production deployment. No Cloudflare account or Firebase project was configured during this coding session. Social media, ads, Swiggy and Zomato are not connected; they need their own official permission flow and successful API test.

## 1. Firebase Google sign-in

1. Open https://console.firebase.google.com/ and create/select a dedicated AJAYNXT Social Hub project.
2. Use the no-cost Spark plan while relying only on free features; do not enable paid services just for sign-in.
3. Project settings > create a Web app. Copy the exact Project ID, API key, Auth domain and App ID.
4. Authentication > Sign-in method: enable Google.
5. Add the actual Cloudflare hostname to Authorized domains after deployment.
6. The Firebase Project ID configured in the Worker must match the project issuing your ID tokens.

Official guide: https://firebase.google.com/docs/auth/web/google-signin

## 2. Clone and install on the MacBook

Open Terminal:

~~~bash
git clone https://github.com/ajaynxt/ajaynxt-superapp.git
cd ajaynxt-superapp
npm install
cp .dev.vars.example .dev.vars
~~~

Edit .dev.vars with the actual Firebase Web app settings. The file is ignored by Git; never commit or share it.

Run checks:

~~~bash
npm run build
npm run check:syntax
npm test
~~~

## 3. Create D1

In the project directory:

~~~bash
npx wrangler login
npx wrangler whoami
npx wrangler d1 create ajaynxt-social-hub
~~~

Cloudflare returns a real database ID. Replace the all-zero placeholder in wrangler.jsonc with the exact returned ID. Never guess this value.

Apply the schema:

~~~bash
npm run db:migrate:remote
~~~

Wrangler records which migrations have run. Do not manually reapply an already applied migration.

## 4. Configure remote Worker secrets

Set these exact Firebase Web values as encrypted Cloudflare Worker secrets:

~~~bash
npx wrangler secret put FIREBASE_PROJECT_ID
npx wrangler secret put FIREBASE_API_KEY
npx wrangler secret put FIREBASE_AUTH_DOMAIN
npx wrangler secret put FIREBASE_APP_ID
~~~

Optionally set FIREBASE_STORAGE_BUCKET and FIREBASE_MESSAGING_SENDER_ID if Firebase provides them. The current app does not use a Firebase service-account private key.

For local testing, put the same values in the ignored .dev.vars file. Do not add the owner UID until you have copied it from Firebase Authentication.

## 5. Deploy and configure the sole Super Admin

~~~bash
npm run deploy
~~~

Wrangler prints the site hostname under workers.dev.

1. Copy the deployed hostname into Firebase Console > Authentication > Settings > Authorized domains.
2. Open the site and use Sign in to sync with your own Google account. At first, workspace creation is blocked because no Super Admin UID has been configured yet. This is intentional.
3. Open Firebase Console > Authentication > Users and copy the exact UID for your personal owner account.
4. In Terminal run:

~~~bash
npx wrangler secret put AJAYNXT_SUPER_ADMIN_UID
~~~

Paste that exact UID when prompted. Never use an email, display name, guessed ID or another user's UID.
5. Reload the deployed app and sign in/sync again. Visit /api/health; ownerAccessConfigured should be true.
6. Open /admin.html. The first valid owner initialization creates your workspace and the default Diamond Restaurant project.

Super Admin status is checked by server-side UID on every privileged request; it is not merely a hidden UI button. There is no client-side owner bypass.

## 6. Create/revoke Admin IDs

Each staff/client user must sign into the app once using Google first. Then, in /admin.html as the configured owner:
- Enter a registered user's email in Platform Admin IDs to create an AJN-ADM-XXXXXXXX identifier.
- Revoke Admin access using the Revoke control. The API also revokes their workspace memberships with role admin.
- Use Workspace Members to assign client_viewer, analyst, operator or admin.
- The admin workspace role is only available to someone with an active platform Admin ID.

Only the configured Super Admin UID can create/revoke platform Admin IDs. Other Admins cannot promote themselves or create another Admin ID. These IDs are access records, not passwords; Google sign-in is still required.

## 7. AI plugin / remote MCP read-only connection

After the Worker is deployed with all four D1 migrations applied, the remote MCP endpoint is:

- MCP endpoint: https://YOUR-WORKER-HOST/mcp
- OAuth authorization-server discovery: https://YOUR-WORKER-HOST/.well-known/oauth-authorization-server
- Protected-resource metadata: https://YOUR-WORKER-HOST/.well-known/oauth-protected-resource

Replace YOUR-WORKER-HOST with the exact hostname printed by Wrangler. Do not use the old Vercel static preview.

### Connect from ChatGPT

1. Open the deployed /admin.html as the configured Super Admin. Confirm the MCP endpoint appears and the Google sign-in works.
2. In ChatGPT on the web, enable Developer mode/create a custom app if that feature is available on your plan and workspace. Open Settings or Workspace settings → Apps → Create (exact UI depends on plan/workspace policy).
3. Use the deployed /mcp URL, choose OAuth when asked, and complete Google sign-in. The consent page lets you select one project or the whole workspace. Approve only the information you intend to share.
4. Let ChatGPT discover the tools and test list_projects and get_growth_report. The server exposes eight read-only tools for projects, metrics, growth, financial summary, sales, costs, drafts and integration status.
5. ChatGPT's current documentation says Pro users can connect custom MCP apps with read/fetch permissions in developer mode; full MCP, including write operations, is available to Business/Enterprise/Edu under their workspace policies. AJAYNXT intentionally offers read-only tools regardless of plan. See https://help.openai.com/en/articles/12584461-developer-mode-and-full-mcp-connectors-in-chatgpt.

For Gemini, Grok and other clients, compatibility depends on the client supporting remote MCP, OAuth 2.0 authorization code + PKCE, dynamic client registration and refresh tokens. If a client does not support this OAuth flow but can send a custom Bearer header, the Admin Console can create a read-only token for 7–90 days. Copy it once and keep it secret; revoke it from the same console when no longer required.

The OAuth/MCP endpoints do not connect Meta, Instagram, Threads, YouTube, Google Ads, Swiggy or Zomato. They only allow the authorized AI client to read information already stored in the selected AJAYNXT workspace. Source accounts still need their own official authentication/API access or report imports.

Optional MCP_ALLOWED_ORIGINS is a comma-separated exact-origin allowlist for MCP requests that include an Origin header. Set only origins verified for the client. Do not use a wildcard. OAuth app/server secrets are stored as hashes or Worker-side values and are not returned by /api/config.

Before remote MCP OAuth clients can register, set an independent rate-limit salt as an encrypted Worker secret (this stores only an IP-derived hash, not the raw IP): generate a random value locally with `openssl rand -hex 32`, then run `npx wrangler secret put MCP_RATE_LIMIT_SALT` and paste that random value at the prompt. The OAuth registration endpoint limits each network to 20 registrations per rolling hour and deletes old rate-limit records after seven days. Never put the salt in Git.

## 8. One-year data retention

After the Worker and D1 migrations are actually deployed, a daily Worker Cron runs at 02:17 UTC. The owner console at /admin.html can display recent cleanup run results or trigger an owner-authorized cleanup manually. This is a destructive operation; it permanently removes eligible rows.

The cleanup rules are:
- Metric, sales and cost observations whose observation date is more than 365 days old are purged in batches.
- Reports, draft content, old scheduled-post records and audit events older than 365 days are purged using their creation/generation timestamps.
- Expired/revoked MCP access tokens and expired OAuth requests/codes/session/refresh records are cleaned up according to their shorter expiry windows.
- Old inactive integration-status records are removed; active integration/account configuration and the workspace/project/user login records are retained so the app does not lose its setup every year.
- Each daily pass is deliberately batch-limited; if a table has a very large backlog, the remaining eligible records are removed in following daily passes. Check cleanup status before assuming the backlog is fully gone.

Important: automatic deletion is not running until the real Cloudflare deployment, D1 database ID and all three migrations are configured successfully. Code and a cron declaration by themselves do not delete data. Back up/export records you must retain before triggering cleanup.

## 9. Current routes and data rules

- /api/health reports service/config health, not external account connection.
- /api/config returns only public Firebase Web settings.
- /api/workspaces and /api/projects list and manage the user's authorized workspace/projects.
- /api/projects/:id/imports and /api/projects/:id/metrics import/read project metrics with duplicate protection.
- /api/projects/:id/reports creates comparisons only with 14 complete consecutive days and trend estimates only with 28 complete consecutive days.
- /api/projects/:id/drafts syncs draft content across devices. It does not publish posts.
- /api/projects/:id/sales, /costs and /financial-report store/reconcile actual financial inputs. Revenue minus recorded costs is not net profit.

No social/ad/marketplace integration should show Connected until official OAuth approval, account authorization and a real provider API test all succeed. The current integrations catalogue is not an active integration.

## 10. Install the PWA

After HTTPS deployment:
- Android: open in Chrome and choose Install app/Add to Home Screen.
- iPhone: open in Safari > Share > Add to Home Screen.

This installs the web app shell, not an App Store or Play Store binary. The service worker does not cache API responses, reports, auth or Admin Console data.

## 11. Before using client data

Run build, syntax and unit tests. Verify no-token requests return 401; unapproved users cannot create/revoke Admin IDs (403); revoked users lose access; and cross-workspace IDs cannot read data. Check backups, retention and delete/restore workflows. Free quotas can stop requests at their limit. Treat user-imported data as unverified until it is reconciled with source reports/invoices.
